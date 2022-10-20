/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint max-len: "off" */
/* eslint no-return-assign: "off" */

'use strict';

const assert = require('bsert');
const wire = require('bns/lib/wire');

const TestUtil = require('../test-util');
const util = new TestUtil();

describe('Basic sync & resolve', function() {
  this.timeout(20000);

  before(async () => {
    await util.open();
  });

  after(async () => {
    await util.close();
  });

  it('should sync', async () => {
    await util.generate(123);
    await util.waitForSync();
  });

  it('should get chain info', async () => {
    const qs = wire.Question.fromJSON({
      name: 'info.chain.hnsd.',
      class: 'HS',
      type: 'TXT'
    });

    const {answer} = await util.resolver.resolve(qs);
    assert.strictEqual(answer.length, 2);

    const height = answer[0].data.txt[0];
    const hash = answer[1].data.txt[0];

    assert.strictEqual(height, '123');
    assert.strictEqual(height, String(util.node.chain.height));
    assert.strictEqual(hash, util.node.chain.tip.hash.toString('hex'));
  });
});
