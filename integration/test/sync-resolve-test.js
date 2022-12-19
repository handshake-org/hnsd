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

  const names = {
    'test-ds': [{
      'type': 'DS',
      'keyTag': 57355,
      'algorithm': 8,
      'digestType': 2,
      'digest': '95a57c3bab7849dbcddf7c72ada71a88146b141110318ca5be672057e865c3e2'
    }],

    'test-ns': [{
      'type': 'NS',
      'ns': 'ns1.hns.'
    }],

    'test-txt': [{
      'type': 'TXT',
      'txt': ['hello world']
    }],

    'test-glue4':[{
      'type': 'GLUE4',
      'ns': 'ns1.outofbailwick.',
      'address': '10.20.30.40'
    }],

    'test-glue4-glue':[{
      'type': 'GLUE4',
      'ns': 'ns1.test-glue4-glue.',
      'address': '10.20.30.40'
    }],

    'test-glue6':[{
      'type': 'GLUE6',
      'ns': 'ns1.outofbailwick.',
      'address': '2600:8805:3e00:1f4a::2000'
    }],

    'test-glue6-glue':[{
      'type': 'GLUE6',
      'ns': 'ns1.test-glue6-glue.',
      'address': '2600:8805:3e00:1f4a::2000'
    }],

    'test-synth4':[{
      'type': 'SYNTH4',
      'address': '127.0.0.2'
    }],

    'test-synth6':[{
      'type': 'SYNTH6',
      'address': '::2'
    }]
  };

  function compareImportantProperties(obj1, obj2, props) {
    for (const prop of props) {
      assert(obj1[prop] && obj2[prop]);
      assert.deepStrictEqual(obj1[prop], obj2[prop]);
    }
  }

  it('should register names and sync', async() => {
    await util.generate(100);
    await util.registerNames(names);
    await util.waitForSync();
  });

  it('should resolve DS', async () => {
    const res = await util.resolver.lookup('test-ds', 'DS');

    assert.strictEqual(res.code, wire.codes.NOERROR);

    assert(res.answer.length);
    const answer = res.answer[0];
    assert.strictEqual(answer.type, wire.types.DS);
    compareImportantProperties(
      answer.data.getJSON(),
      names['test-ds'][0],
      ['keyTag', 'algorithm', 'digestType', 'digest']
    );
  });

  it('should resolve NS', async () => {
    const res = await util.resolver.lookup('test-ns', 'NS');

    assert.strictEqual(res.code, wire.codes.NOERROR);

    assert(res.authority.length);
    const referal = res.authority[0];
    assert.strictEqual(referal.type, wire.types.NS);
    assert.deepStrictEqual(
      referal.data.getJSON()['ns'],
      names['test-ns'][0]['ns']
    );
  });

  it('should resolve TXT', async () => {
    const res = await util.resolver.lookup('test-txt', 'TXT');

    assert.strictEqual(res.code, wire.codes.NOERROR);

    assert(res.answer.length);
    const answer = res.answer[0];
    assert.strictEqual(answer.type, wire.types.TXT);
    assert.deepStrictEqual(
      answer.data.getJSON()['txt'],
      names['test-txt'][0]['txt']
    );
  });

  it('should resolve GLUE4 without glue', async () => {
    const res = await util.resolver.lookup('test-glue4', 'NS');

    assert.strictEqual(res.code, wire.codes.NOERROR);

    assert(!res.additional.length);
    assert(res.authority.length);
    const referal = res.authority[0];
    assert.strictEqual(referal.type, wire.types.NS);
    assert.deepStrictEqual(
      referal.data.getJSON()['ns'],
      names['test-glue4'][0]['ns']
    );
  });

  it('should resolve GLUE4 with glue', async () => {
    const res = await util.resolver.lookup('test-glue4-glue', 'NS');

    assert.strictEqual(res.code, wire.codes.NOERROR);

    assert(res.additional.length);
    assert(res.authority.length);
    const referal = res.authority[0];
    assert.strictEqual(referal.type, wire.types.NS);
    assert.deepStrictEqual(
      referal.data.getJSON()['ns'],
      names['test-glue4-glue'][0]['ns']
    );
    const additional = res.additional[0];
    assert.strictEqual(additional.type, wire.types.A);
    assert.deepStrictEqual(
      additional.data.getJSON()['address'],
      names['test-glue4-glue'][0]['address']
    );
  });

  it('should resolve GLUE6 without glue', async () => {
    const res = await util.resolver.lookup('test-glue6', 'NS');

    assert.strictEqual(res.code, wire.codes.NOERROR);

    assert(!res.additional.length);
    assert(res.authority.length);
    const referal = res.authority[0];
    assert.strictEqual(referal.type, wire.types.NS);
    assert.deepStrictEqual(
      referal.data.getJSON()['ns'],
      names['test-glue6'][0]['ns']
    );
  });

  it('should resolve GLUE6 with glue', async () => {
    const res = await util.resolver.lookup('test-glue6-glue', 'NS');

    assert.strictEqual(res.code, wire.codes.NOERROR);

    assert(res.additional.length);
    assert(res.authority.length);
    const referal = res.authority[0];
    assert.strictEqual(referal.type, wire.types.NS);
    assert.deepStrictEqual(
      referal.data.getJSON()['ns'],
      names['test-glue6-glue'][0]['ns']
    );
    const additional = res.additional[0];
    assert.strictEqual(additional.type, wire.types.AAAA);
    assert.deepStrictEqual(
      additional.data.getJSON()['address'],
      names['test-glue6-glue'][0]['address']
    );
  });

  it('should resolve SYNTH4 with glue', async () => {
    const res = await util.resolver.lookup('test-synth4', 'NS');

    assert.strictEqual(res.code, wire.codes.NOERROR);

    assert(res.additional.length);
    assert(res.authority.length);
    const referal = res.authority[0];
    assert.strictEqual(referal.type, wire.types.NS);
    assert.deepStrictEqual(
      referal.data.getJSON()['ns'],
      '_fs0000g._synth.'
    );
    const additional = res.additional[0];
    assert.strictEqual(additional.type, wire.types.A);
    assert.deepStrictEqual(
      additional.data.getJSON()['address'],
      names['test-synth4'][0]['address']
    );
  });

  it('should resolve SYNTH6 with glue', async () => {
    const res = await util.resolver.lookup('test-synth6', 'NS');

    assert.strictEqual(res.code, wire.codes.NOERROR);

    assert(res.additional.length);
    assert(res.authority.length);
    const referal = res.authority[0];
    assert.strictEqual(referal.type, wire.types.NS);
    assert.deepStrictEqual(
      referal.data.getJSON()['ns'],
      '_00000000000000000000000008._synth.'
    );
    const additional = res.additional[0];
    assert.strictEqual(additional.type, wire.types.AAAA);
    assert.deepStrictEqual(
      additional.data.getJSON()['address'],
      names['test-synth6'][0]['address']
    );
  });

  describe('synth', function () {
    it('should get SOA when querying _synth.', async () => {
      const res = await util.resolver.lookup('_synth.', 'NS');

      assert.strictEqual(res.code, wire.codes.NOERROR);

      assert(res.authority.length);
      const referal = res.authority[0];
      assert.strictEqual(referal.type, wire.types.SOA);
    });

    it('should resolve valid synth address', async () => {
      const res = await util.resolver.lookup('_5l6tm80._synth.', 'A');

      assert.strictEqual(res.code, wire.codes.NOERROR);

      assert(res.answer.length);
      const answer = res.answer[0];
      assert.strictEqual(answer.type, wire.types.A);
      assert.deepStrictEqual(
        answer.data.getJSON()['address'],
        '45.77.219.32'
      );
    });
  });
});
