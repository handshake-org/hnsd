
'use strict';

const assert = require('bsert');
const {spawn} = require('child_process');
const path = require('path');
const {FullNode, packets} = require('hsd');
const wire = require('bns/lib/wire');
const StubResolver = require('bns/lib/resolver/stub');

class TestUtil {
  constructor(options) {
    this.node = new FullNode({
      memory: true,
      network: 'regtest',
      listen: true,
      port: 10000,
      noDns: true,
      plugins: [require('hsd/lib/wallet/plugin')]
    });

    this.packets = {};
    this.node.pool.on('packet', (packet) => {
      const type = packets.typesByVal[packet.type];
      if (!this.packets[type])
        this.packets[type] = [packet];
      else
        this.packets[type].push(packet);
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

  async open() {
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
        {stdio: 'ignore'} // pro tip: switch to 'inherit' to see hnsd output
      );

      this.hnsd.on('spawn', () => resolve(this.hnsd));
      this.hnsd.on('error', e => reject(e));
    });
  }

  closeHNSD() {
    if (!this.hnsd)
      return;

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
