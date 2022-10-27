/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint max-len: "off" */
/* eslint no-return-assign: "off" */

'use strict';

const assert = require('bsert');
const {version} = require('../package.json');

const TestUtil = require('../test-util');
const util = new TestUtil();

describe('Configuration', function() {
  this.timeout(5000);

  before(async () => {
    await util.open();
  });

  after(async () => {
    await util.close();
  });

  describe('--agent', function () {
    it('should have default user agent', async () => {
      await util.generate(1);
      await util.waitForSync();

      const peer = util.node.pool.peers.head();
      assert.strictEqual(peer.agent, `/hnsd:${version}/`);
    });

    it('should fail to start with too-long agent', async () => {
      const agent = 'x'.repeat(255 - `/hnsd:${version}/`.length);
      const hnsd = await util.restartHNSD(['-a', agent]);
      await new Promise((resolve) => {
        hnsd.once('exit', (code, signal) => {
          assert.strictEqual(code, 3); // HSK_EFAILURE
          resolve();
        });
      });
    });

    it('should fail to start with backslash-containing agent', async () => {
      const agent = 'beacon/browser/verifies/dane';
      const hnsd = await util.restartHNSD(['-a', agent]);
      await new Promise((resolve) => {
        hnsd.once('exit', (code, signal) => {
          assert.strictEqual(code, 3); // HSK_EFAILURE
          resolve();
        });
      });
    });

    it('should have custom user agent', async () => {
      const agent = 'x'.repeat(255 - `/hnsd:${version}/`.length - 1);
      await util.restartHNSD(['-a', agent]);
      await util.generate(1);
      await util.waitForSync();

      const peer = util.node.pool.peers.head();
      assert.strictEqual(peer.agent, `/hnsd:${version}/${agent}/`);
    });
  });
});
