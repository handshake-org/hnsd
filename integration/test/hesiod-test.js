/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint max-len: "off" */
/* eslint no-return-assign: "off" */

'use strict';

const assert = require('bsert');
const wire = require('bns/lib/wire');
const {pkg} = require('hsd');

const TestUtil = require('../test-util');
const util = new TestUtil();

describe('Hesiod', function() {
  this.timeout(30000);

  before(async () => {
    await util.open();
  });

  after(async () => {
    await util.close();
  });

  describe('Chain', function () {
    it('should not be synced', async () => {
      const qs = wire.Question.fromJSON({
        name: 'synced.chain.hnsd.',
        class: 'HS',
        type: 'TXT'
      });

      const {answer} = await util.resolver.resolve(qs);
      assert.strictEqual(answer.length, 1);

      assert.strictEqual(answer[0].data.txt[0], 'false');
    });

    it('should sync', async () => {
      await util.generate(3000); // ensures at least 2x 2000-headers packets
      await util.waitForSync();
    });

    it('should be synced', async () => {
      const qs = wire.Question.fromJSON({
        name: 'synced.chain.hnsd.',
        class: 'HS',
        type: 'TXT'
      });

      const {answer} = await util.resolver.resolve(qs);
      assert.strictEqual(answer.length, 1);

      assert.strictEqual(answer[0].data.txt[0], 'true');
    });

    it('should get chain tip hash', async () => {
      const qs = wire.Question.fromJSON({
        name: 'hash.tip.chain.hnsd.',
        class: 'HS',
        type: 'TXT'
      });

      const {answer} = await util.resolver.resolve(qs);
      assert.strictEqual(answer.length, 1);

      const hash = answer[0].data.txt[0];
      assert.strictEqual(hash, util.node.chain.tip.hash.toString('hex'));
    });

    it('should get chain tip height', async () => {
      const qs = wire.Question.fromJSON({
        name: 'height.tip.chain.hnsd.',
        class: 'HS',
        type: 'TXT'
      });

      const {answer} = await util.resolver.resolve(qs);
      assert.strictEqual(answer.length, 1);

      const height = answer[0].data.txt[0];
      assert.strictEqual(height, '3000');
      assert.strictEqual(height, String(util.node.chain.tip.height));
    });

    it('should get chain tip time', async () => {
      const qs = wire.Question.fromJSON({
        name: 'time.tip.chain.hnsd.',
        class: 'HS',
        type: 'TXT'
      });

      const {answer} = await util.resolver.resolve(qs);
      assert.strictEqual(answer.length, 1);

      const time = answer[0].data.txt[0];
      assert.strictEqual(time, String(util.node.chain.tip.time));
    });

    it('generate more blocks', async () => {
      await util.generate(3000); // ensures at least 2x 2000-headers packets
      await util.waitForSync();
    });

    it('should get all chain info', async () => {
      const qs = wire.Question.fromJSON({
        name: 'chain.hnsd.',
        class: 'HS',
        type: 'TXT'
      });

      const {answer} = await util.resolver.resolve(qs);
      assert.strictEqual(answer.length, 6);

      assert.strictEqual(answer[0].name, 'hash.tip.chain.hnsd.');
      assert.strictEqual(answer[0].data.txt[0], util.node.chain.tip.hash.toString('hex'));

      assert.strictEqual(answer[1].name, 'height.tip.chain.hnsd.');
      assert.strictEqual(answer[1].data.txt[0], String(util.node.chain.tip.height));
      assert.strictEqual(answer[1].data.txt[0], '6000');

      assert.strictEqual(answer[2].name, 'name_root.tip.chain.hnsd.');
      assert.strictEqual(answer[2].data.txt[0], util.node.chain.tip.treeRoot.toString('hex'));

      assert.strictEqual(answer[3].name, 'time.tip.chain.hnsd.');
      assert.strictEqual(answer[3].data.txt[0], String(util.node.chain.tip.time));

      assert.strictEqual(answer[4].name, 'synced.chain.hnsd.');
      assert.strictEqual(answer[4].data.txt[0], 'true');

      assert.strictEqual(answer[5].name, 'progress.chain.hnsd.');
      assert.strictEqual(answer[5].data.txt[0], '1.000000');
    });
  });

  describe('Pool', function () {
    it('should have no peers', async () => {
      // Disconnect
      await util.node.pool.close();
      await util.waitForHS('size.pool.hnsd.', 0);

      const qs = wire.Question.fromJSON({
        name: 'pool.hnsd.',
        class: 'HS',
        type: 'TXT'
      });

      const {answer} = await util.resolver.resolve(qs);
      assert.strictEqual(answer.length, 1);

      assert.strictEqual(answer[0].name, 'size.pool.hnsd.');
      assert.strictEqual(answer[0].data.txt[0], '0');
    });

    it('should have peer info', async () => {
      // Reconnect
      await util.node.pool.open();
      await util.node.pool.connect();
      await util.generate(1);
      await util.waitForSync();

      const qs = wire.Question.fromJSON({
        name: 'pool.hnsd.',
        class: 'HS',
        type: 'TXT'
      });

      const {answer} = await util.resolver.resolve(qs);
      assert.strictEqual(answer.length, 6);

      assert.strictEqual(answer[0].name, 'size.pool.hnsd.');
      assert.strictEqual(answer[0].data.txt[0], '1');

      assert.strictEqual(answer[1].name, 'host.0.peers.pool.hnsd.');
      assert.strictEqual(answer[1].data.txt[0], `${util.host}:${util.port}`);

      assert.strictEqual(answer[2].name, 'agent.0.peers.pool.hnsd.');
      assert.strictEqual(answer[2].data.txt[0], `/${pkg.name}:${pkg.version}/`);

      assert.strictEqual(answer[3].name, 'headers.0.peers.pool.hnsd.');
      assert.strictEqual(answer[3].data.txt[0], '1');

      assert.strictEqual(answer[4].name, 'proofs.0.peers.pool.hnsd.');
      assert.strictEqual(answer[4].data.txt[0], '0');

      assert.strictEqual(answer[5].name, 'state.0.peers.pool.hnsd.');
      assert.strictEqual(answer[5].data.txt[0], 'HSK_STATE_HANDSHAKE');
    });

    it('should count more headers', async () => {
      await util.generate(10);
      await util.waitForSync();

      const qs = wire.Question.fromJSON({
        name: 'peers.pool.hnsd.',
        class: 'HS',
        type: 'TXT'
      });

      const {answer} = await util.resolver.resolve(qs);
      assert.strictEqual(answer[2].name, 'headers.0.peers.pool.hnsd.');
      assert.strictEqual(answer[2].data.txt[0], '11');
    });

    it('should count proof requests', async () => {
      const qs = wire.Question.fromJSON({
        name: 'peers.pool.hnsd.',
        class: 'HS',
        type: 'TXT'
      });

      await util.resolver.lookup('fake', 'NS');

      const res1 = await util.resolver.resolve(qs);
      assert.strictEqual(res1.answer[3].name, 'proofs.0.peers.pool.hnsd.');
      assert.strictEqual(res1.answer[3].data.txt[0], '1');

      await util.resolver.lookup('phony', 'NS');

      const res2 = await util.resolver.resolve(qs);
      assert.strictEqual(res2.answer[3].name, 'proofs.0.peers.pool.hnsd.');
      assert.strictEqual(res2.answer[3].data.txt[0], '2');
    });
  });
});
