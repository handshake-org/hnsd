/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint max-len: "off" */
/* eslint no-return-assign: "off" */

'use strict';

const assert = require('bsert');
const wire = require('bns/lib/wire');

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

  it('should sync', async () => {
    await util.generate(3000); // ensures at least 2x 2000-headers packets
    await util.waitForSync();
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
    assert.strictEqual(answer.length, 3);

    const [hashTxt, heightTxt, timeTxt] = answer;

    assert.strictEqual(hashTxt.name, 'hash.tip.chain.hnsd.');
    assert.strictEqual(hashTxt.data.txt[0], util.node.chain.tip.hash.toString('hex'));

    assert.strictEqual(heightTxt.name, 'height.tip.chain.hnsd.');
    assert.strictEqual(heightTxt.data.txt[0], String(util.node.chain.tip.height));
    assert.strictEqual(heightTxt.data.txt[0], '6000');

    assert.strictEqual(timeTxt.name, 'time.tip.chain.hnsd.');
    assert.strictEqual(timeTxt.data.txt[0], String(util.node.chain.tip.time));
  });
});
