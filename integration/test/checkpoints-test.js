/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint max-len: "off" */
/* eslint no-return-assign: "off" */

'use strict';

const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('bsert');
const TestUtil = require('../test-util');
const util = new TestUtil();

describe('Checkpoints', function() {
  this.timeout(20000);

  let tmpdir = os.tmpdir();
  tmpdir = path.join(tmpdir, `hnsd-test-${Date.now()}`);

  before(async () => {
    await fs.mkdirSync(tmpdir);
    util.extraArgs(['-x', tmpdir]); // enable automatic checkpoints on disk
    await util.open();
  });

  after(async () => {
    await util.close();
  });

  beforeEach(() => {
    util.resetPackets();
  });

  async function hashesToHeights(hashes) {
    assert(Array.isArray(hashes));

    const heights = [];
    for (const hash of hashes)
      heights.push(await util.node.chain.getMainHeight(hash));

    return heights;
  }

  it('should initial sync', async() => {
    await util.generate(1000);
    await util.waitForSync();

    assert(util.packetsFrom.GETHEADERS.length);
    const {locator} = util.packetsFrom.GETHEADERS.shift();

    // Just the genesis block
    assert.strictEqual(locator.length, 1);
    assert.bufferEqual(locator[0], util.node.network.genesis.hash);
  });

  it('should restart from checkpoint with no peers', async () => {
    // Disconnect full node
    await util.node.pool.close();

    await util.restartHNSD(['-x', tmpdir]);

    // Sanity check: these blocks should not be received by hnsd
    await util.generate(100);

    // Last height hnsd synced to was 1000.
    // It should have saved a checkpoint containing the first 150
    // blocks of the checkpoint window which on regtest is 200 blocks.
    // Upon restart, it should automatically intialize through that checkpoint.
    const {hnsd} = await util.getHeights();
    assert.strictEqual(hnsd, 949);
  });

  it('should continue syncing after starting from checkpoint', async () => {
    // Reconnect full node
    await util.node.pool.open();
    await util.node.pool.connect();

    await util.waitForSync();
    const {hnsd, hsd} = await util.getHeights();
    assert.strictEqual(hsd, hnsd);
    assert.strictEqual(hnsd, 1100);

    // Full node sent 151 headers, starting at height 950
    assert(util.packetsTo.HEADERS.length);
    const {items} = util.packetsTo.HEADERS.shift();
    assert.strictEqual(items.length, 151);
    const hashes = items.map(h => h.hash());
    const heights = await hashesToHeights(hashes);
    assert.strictEqual(heights[0], 950);
  });

  it('should restart from checkpoint and resync', async () => {
    await util.restartHNSD(['-x', tmpdir]);
    await util.waitForSync();

    assert(util.packetsFrom.GETHEADERS.length);
    const {locator} = util.packetsFrom.GETHEADERS.shift();
    const locatorHeights = await hashesToHeights(locator);

    assert.deepStrictEqual(
      locatorHeights,
      [
        949, // tip
             // 10 prev blocks
        948, 947, 946, 945, 944, 943, 942, 941, 940, 939,
        938, // -1
        936, // -2
        932, // -4
        924, // -8
        908, // -16
        876, // -32
        812, // -64
        0    // hnsd doesn't have any blocks lower than 800, so skip to genesis
      ]
    );

    const {hnsd, hsd} = await util.getHeights();
    assert.strictEqual(hsd, hnsd);
    assert.strictEqual(hnsd, 1100);

    // Full node sent 151 headers, starting at height 950
    assert(util.packetsTo.HEADERS.length);
    const {items} = util.packetsTo.HEADERS.shift();
    assert.strictEqual(items.length, 151);
    const hashes = items.map(h => h.hash());
    const headersHeights = await hashesToHeights(hashes);
    assert.strictEqual(headersHeights[0], 950);
  });

  it('should resync from checkpoint after a reorg (after)', async () => {
    // Disconnect full node
    await util.node.pool.close();

    // Reorg chain
    // Fork point comes AFTER checkpoint
    const hash = await util.node.chain.getHash(1001);
    await util.node.chain.invalidate(hash);
    {
      const {hsd, hnsd} = await util.getHeights();
      assert.strictEqual(hsd, 1000);
      assert.strictEqual(hnsd, 1100);
    }
    await util.generate(110);

    // Reconnect full node
    util.resetPackets();
    await util.restartHNSD(['-x', tmpdir]);
    await util.node.pool.open();
    await util.node.pool.connect();

    await util.waitForSync();
    const {hnsd, hsd} = await util.getHeights();
    assert.strictEqual(hsd, hnsd);
    assert.strictEqual(hnsd, 1110);

    // Full node sent 161 headers, starting at height 950
    // (reorg fork was at height 930, last locator hash was at 949)
    assert(util.packetsTo.HEADERS.length);
    const {items} = util.packetsTo.HEADERS.shift();
    assert.strictEqual(items.length, 161);
    const hashes = items.map(h => h.hash());
    const headersHeights = await hashesToHeights(hashes);
    assert.strictEqual(headersHeights[0], 950);
  });

  it('should resync from checkpoint after a reorg (inside)', async () => {
    // Disconnect full node
    await util.node.pool.close();

    // Reorg chain
    // Fork point comes INSIDE checkpoint
    const hash = await util.node.chain.getHash(931);
    await util.node.chain.invalidate(hash);
    {
      const {hsd, hnsd} = await util.getHeights();
      assert.strictEqual(hsd, 930);
      assert.strictEqual(hnsd, 1110);
    }
    await util.generate(190);

    // Reconnect full node
    util.resetPackets();
    await util.restartHNSD(['-x', tmpdir]);
    await util.node.pool.open();
    await util.node.pool.connect();

    await util.waitForSync();
    const {hnsd, hsd} = await util.getHeights();
    assert.strictEqual(hsd, hnsd);
    assert.strictEqual(hnsd, 1120);

    // Full node sent 196 headers, starting at height 925
    // (reorg fork was at height 930, previous locator hash was at 924)
    assert(util.packetsTo.HEADERS.length);
    const {items} = util.packetsTo.HEADERS.shift();
    assert.strictEqual(items.length, 196);
    const hashes = items.map(h => h.hash());
    const headersHeights = await hashesToHeights(hashes);
    assert.strictEqual(headersHeights[0], 925);
  });

  it('should resync from checkpoint after a reorg (before)', async () => {
    // Disconnect full node
    await util.node.pool.close();

    // Reorg chain
    // Fork point comes BEFORE checkpoint
    const hash = await util.node.chain.getHash(801);
    await util.node.chain.invalidate(hash);
    {
      const {hsd, hnsd} = await util.getHeights();
      assert.strictEqual(hsd, 800);
      assert.strictEqual(hnsd, 1120);
    }
    await util.generate(330);

    // Reconnect full node
    await util.restartHNSD(['-x', tmpdir]);
    await util.node.pool.open();
    await util.node.pool.connect();

    await util.waitForSync();
    const {hnsd, hsd} = await util.getHeights();
    assert.strictEqual(hsd, hnsd);
    assert.strictEqual(hnsd, 1130);

    // Full node sent 1130 headers, starting at height 1
    // (reorg fork was at height 800, previous locator hash was at 0)
    assert(util.packetsTo.HEADERS.length);
    const {items} = util.packetsTo.HEADERS.shift();
    assert.strictEqual(items.length, 1130);
    const hashes = items.map(h => h.hash());
    const headersHeights = await hashesToHeights(hashes);
    assert.strictEqual(headersHeights[0], 1);
  });

  it('should survive all that', async () => {
    const hash = await util.resolveHS('hash.tip.chain.hnsd.');
    assert.strictEqual(
      hash,
      util.node.chain.tip.hash.toString('hex')
    );
  });
});
