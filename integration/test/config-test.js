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
  this.timeout(10000);

  before(async () => {
    await util.open();
  });

  after(async () => {
    await util.close();
  });

  function waitForStartFailure(expectedMsg, expectedCode) {
    return new Promise((resolve, reject) => {
      let gotMsg = false;
      let gotCode = false;
      let error = null;

      function maybeResolve() {
        if (!gotMsg || !gotCode)
          return;

        if (error)
          reject(error);
        else
          resolve();
      }

      function fail(actual, expected) {
        error = new assert.AssertionError({
          message: 'hnsd start failure with unexpected output',
          actual,
          expected,
          operator: 'equal'
        });
      }

      function handleErr(msg) {
        if (!msg.match(expectedMsg))
          fail(msg, expectedMsg);
        gotMsg = true;
        maybeResolve();
      }

      function handleClose(code) {
        if (code !== expectedCode)
          fail(code, expectedCode);
        gotCode = true;
        maybeResolve();
      }

      util.once('stderr', handleErr);
      util.once('close', handleClose);
    });
  }

  describe('--agent', function () {
    it('should have default user agent', async () => {
      await util.generate(1);
      await util.waitForSync();

      const peer = util.node.pool.peers.head();
      assert.strictEqual(peer.agent, `/hnsd:${version}/`);
      await util.closeHNSD();
    });

    it('should fail to start with too-long agent', async () => {
      const waiter = waitForStartFailure(
        /failed adding user agent/,
        3 // HSK_EBADARGS
      );

      const agent = 'x'.repeat(255 - `/hnsd:${version}/`.length);
      await util.restartHNSD(['-a', agent]);
      await waiter;
    });

    it('should fail to start with backslash-containing agent', async () => {
      const waiter = waitForStartFailure(
        /failed adding user agent/,
        3 // HSK_EBADARGS
      );

      const agent = 'beacon/browser/verifies/dane';
      await util.restartHNSD(['-a', agent]);
      await waiter;
    });

    it('should have custom user agent', async () => {
      const agent = 'x'.repeat(255 - `/hnsd:${version}/`.length - 1);
      await util.restartHNSD(['-a', agent]);
      await util.generate(1);
      await util.waitForSync();

      const peer = util.node.pool.peers.head();
      assert.strictEqual(peer.agent, `/hnsd:${version}/${agent}/`);
      await util.closeHNSD();
    });
  });
});
