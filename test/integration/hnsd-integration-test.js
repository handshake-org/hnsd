/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint max-len: "off" */
/* eslint no-return-assign: "off" */
'use strict';

const {spawn} = require('child_process');
const path = require('path');
const assert = require('bsert');
const {FullNode} = require('hsd');
const dns = require('bns/lib/dns');
const wire = require('bns/lib/wire');

describe('hnsd Integration Test', function() {
  const node = new FullNode({
    memory: true,
    network: 'regtest',
    listen: true,
    port: 10000,
    noDns: true,
    plugins: [require('hsd/lib/wallet/plugin')]
  });

  const resolver = new dns.Resolver({
    host: '127.0.0.1',
    port: 25349,
    dnssec: true
  });
  resolver.setServers(['127.0.0.1:25349']);

  const hnsdPath = path.join(__dirname, '..', '..', 'hnsd');
  let hnsd;

  function find(rrs, type) {
    for (const rr of rrs) {
      // return first found
      if (rr.type === wire.types[type])
        return rr;
    }
    return null;
  }

  before(async () => {
    await node.open();
    await node.connect();

    hnsd = spawn(
      hnsdPath,
      ['-s', '127.0.0.1:10000'],
      {shell: false}
    );
  });

  after(async () => {
    hnsd.kill('SIGKILL');
    await node.close();
  });

  it('should register names', async() => {
    const addr = await node.plugins.walletdb.rpc.getNewAddress(['default']);
    await node.rpc.generateToAddress([100, addr]);
    await node.plugins.walletdb.rpc.sendOpen(['test-ds']);
    await node.plugins.walletdb.rpc.sendOpen(['test-ns']);
    await node.plugins.walletdb.rpc.sendOpen(['test-txt']);
    await node.plugins.walletdb.rpc.sendOpen(['test-glue4-glue']);
    await node.rpc.generateToAddress([6, addr]);
    await node.plugins.walletdb.rpc.sendBid(['test-ds', 1, 1]);
    await node.plugins.walletdb.rpc.sendBid(['test-ns', 1, 1]);
    await node.plugins.walletdb.rpc.sendBid(['test-txt', 1, 1]);
    await node.plugins.walletdb.rpc.sendBid(['test-glue4-glue', 1, 1]);
    await node.rpc.generateToAddress([6, addr]);
    await node.plugins.walletdb.rpc.sendReveal([]);
    await node.rpc.generateToAddress([10, addr]);
    await node.plugins.walletdb.rpc.sendUpdate([
      'test-ds',
      {
        'records':
        [
          {
            'type': 'DS',
            'keyTag': 57355,
            'algorithm': 8,
            'digestType': 2,
            'digest': '95a57c3bab7849dbcddf7c72ada71a88146b141110318ca5be672057e865c3e2'
          }
        ]
      }
    ]);
    await node.plugins.walletdb.rpc.sendUpdate([
      'test-ns',
      {
        'records':
        [
          {
            'type': 'NS',
            'ns': 'ns1.hns.'
          }
        ]
      }
    ]);
    await node.plugins.walletdb.rpc.sendUpdate([
      'test-txt',
      {
        'records':
        [
          {
            'type': 'TXT',
            'txt': ['hello world']
          }
        ]
      }
    ]);
    await node.plugins.walletdb.rpc.sendUpdate([
      'test-glue4-glue',
      {
        'records':
        [
          {
            'type': 'GLUE4',
            'ns': 'ns1.test-glue4-glue.',
            'address': '10.20.30.40'
          }
        ]
      }
    ]);
    await node.rpc.generateToAddress([10, addr]);
  });

  it('doesnotexist / A', async() => {
    const result = await resolver.resolveRaw('doesnotexist.', 'A');
    const nsec = find(result.authority, 'NSEC');
    assert(nsec);
    assert.strictEqual(nsec.name, 'doesnotexiss\\255.');
    assert.strictEqual(nsec.data.nextDomain, 'doesnotexist\\000.');
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.NSEC));
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.RRSIG));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.A));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.AAAA));
  });

  it('_synth / A', async() => {
    const result = await resolver.resolveRaw('_synth.', 'A');
    const nsec = find(result.authority, 'NSEC');
    assert(nsec);
    assert.strictEqual(nsec.name, '_synth.');
    assert.strictEqual(nsec.data.nextDomain, '\\000._synth.');
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.NSEC));
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.RRSIG));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.A));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.AAAA));
  });

  it('_fs00008._synth. / A', async() => {
    const result = await resolver.resolveRaw('_fs00008._synth.', 'A');
    const a = find(result.answer, 'A');
    assert(a);
    assert.strictEqual(a.data.address, '127.0.0.1');
  });

  it('_fs00008._synth. / AAAA', async() => {
    const result = await resolver.resolveRaw('_fs00008._synth.', 'AAAA');
    const nsec = find(result.authority, 'NSEC');
    assert(nsec);
    assert.strictEqual(nsec.name, '_fs00008._synth.');
    assert.strictEqual(nsec.data.nextDomain, '\\000._fs00008._synth.');
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.A));
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.NSEC));
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.RRSIG));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.AAAA));
  });

  it('badsynth._synth. / A', async() => {
    const result = await resolver.resolveRaw('badsynth._synth.', 'A');
    assert.strictEqual(result.question[0].name, 'badsynth._synth.');
    assert.strictEqual(result.code, wire.codes.REFUSED);
  });

  it('test-ds / DS', async() => {
    const result = await resolver.resolveRaw('test-ds.', 'DS');
    assert(result.authority.length === 0);
    const ds = find(result.answer, 'DS');
    assert(ds);
    assert.bufferEqual(
      ds.data.digest,
      Buffer.from('95a57c3bab7849dbcddf7c72ada71a88146b141110318ca5be672057e865c3e2', 'hex')
    );
  });

  it('test-ds / NS', async() => {
    const result = await resolver.resolveRaw('test-ds.', 'NS');
    const nsec = find(result.authority, 'NSEC');
    assert(nsec);
    assert.strictEqual(nsec.name, 'test-ds.');
    assert.strictEqual(nsec.data.nextDomain, 'test-ds\\000.');
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.NSEC));
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.RRSIG));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.DS));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.NS));
  });

  it('test-ns / NS', async() => {
    const result = await resolver.resolveRaw('test-ns.', 'NS');
    const ns = find(result.authority, 'NS');
    assert(ns);
    assert.strictEqual(ns.data.ns, 'ns1.hns.');

    const nsec = find(result.authority, 'NSEC');
    assert(nsec);
    assert.strictEqual(nsec.name, 'test-ns.');
    assert.strictEqual(nsec.data.nextDomain, 'test-ns\\000.');
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.NSEC));
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.RRSIG));
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.NS));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.DS));
  });

  it('test-txt / TXT', async() => {
    const result = await resolver.resolveRaw('test-txt.', 'TXT');
    const txt = find(result.answer, 'TXT');
    assert(txt);
    assert.strictEqual(txt.data.txt[0], 'hello world');
  });

  it('test-txt / NS', async() => {
    const result = await resolver.resolveRaw('test-txt.', 'NS');
    const nsec = find(result.authority, 'NSEC');
    assert(nsec);
    assert.strictEqual(nsec.name, 'test-txt.');
    assert.strictEqual(nsec.data.nextDomain, 'test-txt\\000.');
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.NSEC));
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.RRSIG));
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.TXT));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.DS));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.NS));
  });

  it('test-glue4-glue / NS', async() => {
    const result = await resolver.resolveRaw('test-glue4-glue.', 'NS');
    const ns = find(result.authority, 'NS');
    assert(ns);
    assert.strictEqual(ns.data.ns, 'ns1.test-glue4-glue.');

    const a = find(result.additional, 'A');
    assert(a);
    assert.strictEqual(a.data.address, '10.20.30.40');

    const nsec = find(result.authority, 'NSEC');
    assert(nsec);
    assert.strictEqual(nsec.name, 'test-glue4-glue.');
    assert.strictEqual(nsec.data.nextDomain, 'test-glue4-glue\\000.');
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.NSEC));
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.RRSIG));
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.NS));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.TXT));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.DS));
  });

  it('foo\\200 / A', async() => {
    const result = await resolver.resolveRaw('foo\\200.', 'A');
    assert.strictEqual(result.question[0].name, 'foo\\200.');
    assert.strictEqual(result.code, wire.codes.REFUSED);
  });

  it('\\\\ducks.doesnotexist2. / A', async() => {
    const result = await resolver.resolveRaw('\\\\ducks.doesnotexist2.', 'A');
    assert.strictEqual(result.question[0].name, '\\\\ducks.doesnotexist2.');

    const nsec = find(result.authority, 'NSEC');
    assert(nsec);
    assert.strictEqual(nsec.name, 'doesnotexist1\\255.');
    assert.strictEqual(nsec.data.nextDomain, 'doesnotexist2\\000.');
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.NSEC));
    assert(nsec.data.toJSON().typeBitmap.includes(wire.types.RRSIG));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.NS));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.TXT));
    assert(!nsec.data.toJSON().typeBitmap.includes(wire.types.DS));
  });
});
