
'use strict';

const {spawn, execSync} = require('child_process');
const assert = require('bsert');
const path = require('path');
const {FullNode, packets} = require('hsd');
const wire = require('bns/lib/wire');
const StubResolver = require('bns/lib/resolver/stub');
const {EOL} = require('os');
const {version} = require('./package.json');
const network = 'regtest';
const hnsdPath = path.join(__dirname, '..', 'hnsd');

class TestUtil {
  constructor(options) {
    this.host = '127.0.0.1';
    this.port = 10000;

    this.node = new FullNode({
      memory: true,
      network,
      listen: true,
      host: this.host,
      port: this.port,
      brontidePort: 46888, // avoid hnsd connecting via brontide
      noDns: true,
      plugins: [require('hsd/lib/wallet/plugin')]
    });

    // Packets received by full node from hnsd
    this.packetsFrom = {};
    this.node.pool.on('packet', (packet) => {
      const type = packets.typesByVal[packet.type];
      if (!this.packetsFrom[type])
        this.packetsFrom[type] = [packet];
      else
        this.packetsFrom[type].push(packet);
    });

    // Packets sent to hnsd by the full node
    this.packetsTo = {};
    this.node.pool.on('peer open', (peer) => {
      peer.SEND = peer.send;

      peer.send = (packet) => {
        const type = packets.typesByVal[packet.type];
        if (!this.packetsTo[type])
          this.packetsTo[type] = [packet];
        else
          this.packetsTo[type].push(packet);

        peer.SEND(packet);
      };
    });

    this.wallet = null;

    this.resolver = new StubResolver();
    this.resolver.setServers(['127.0.0.1:25349']);

    this.hnsd = null;
    this.hnsdHeight = 0;
    this.hnsdArgsBase = ['-s', '127.0.0.1:10000'];
    this.hnsdArgs = this.hnsdArgsBase;
  }

  extraArgs(args) {
    assert(Array.isArray(args));
    this.hnsdArgs = this.hnsdArgs.concat(args);
  }

  resetPackets() {
    this.packetsTo = {};
    this.packetsFrom = {};
  }

  async open() {
    const hnsdVersion = (await execSync(hnsdPath + ' -v')).toString('ascii');
    assert.strictEqual(
      hnsdVersion,
      `${version} (${network})` + EOL,
      'Network or version mismatch'
    );

    await this.resolver.open();
    await this.node.open();
    await this.node.connect();

    this.wallet = this.node.plugins.walletdb;

    return this.openHNSD();
  }

  async close() {
    this.closeHNSD();
    await this.node.close();
  }

  async openHNSD() {
    return new Promise((resolve, reject) => {
      this.hnsd = spawn(
        path.join(__dirname, '..', 'hnsd'),
        this.hnsdArgs,
        {stdio: 'ignore'}
      );

      this.hnsd.on('spawn', () => resolve());
      this.hnsd.on('error', () => reject());
      this.hnsd.on('close', this.crash);
    });
  }

  crash(code, signal) {
    throw new Error(`hnsd crashed with code: ${code} and signal: ${signal}`);
  }

  closeHNSD() {
    if (!this.hnsd)
      return;

    this.hnsd.removeListener('close', this.crash);

    this.hnsd.kill('SIGKILL');
    this.hnsd = null;
  }

  async restartHNSD(args) {
    this.closeHNSD();

    if (args) {
      assert(Array.isArray(args));
      this.hnsdArgs = this.hnsdArgsBase.concat(args);
    }

    return this.openHNSD();
  }

  async getWalletAddress() {
    return this.wallet.rpc.getNewAddress(['default']);
  }

  async generate(n) {
    const addr = await this.getWalletAddress();
    await this.node.rpc.generateToAddress([n, addr]);
  }

  // names: Object with name:records[] mapping
  async registerNames(names) {
    for (const name of Object.keys(names)) {
      await this.wallet.rpc.sendOpen([name]);
    }
    await this.generate(6);

    for (const name of Object.keys(names)) {
      await this.wallet.rpc.sendBid([name, 1, 1]);
    }

    await this.generate(6);
    await this.wallet.rpc.sendReveal([]);

    await this.generate(10);
    for (const name of Object.keys(names)) {
      await this.wallet.rpc.sendUpdate([name, {records: names[name]}]);
    }
    await this.generate(12); // safe root
  }

  async resolveHS(name) {
    const qs = wire.Question.fromJSON({
      name,
      class: 'HS',
      type: 'TXT'
    });

    const {answer} = await this.resolver.resolve(qs);
    assert(answer && answer.length);
    return answer[0].data.txt[0];
  }

  async waitForHS(name, value) {
    const answer = await this.resolveHS(name);
    if (answer === String(value))
      return value;

    return new Promise(async (resolve) => {
      setTimeout(async () => {
        resolve(this.waitForHS(name));
      }, 100);
    });
  }

  async getHeights() {
    const hnsd = this.hnsd
                 ? await this.resolveHS('height.tip.chain.hnsd.')
                 : 0;

    return {
      hnsd: parseInt(hnsd),
      hsd: this.node.chain.height
    };
  }

  async waitForSync() {
    const {hsd, hnsd} = await this.getHeights();
    if (hsd === hnsd)
      return hnsd;

    return new Promise(async (resolve) => {
      setTimeout(async () => {
        resolve(this.waitForSync());
      }, 100);
    });
  }
}

module.exports = TestUtil;
