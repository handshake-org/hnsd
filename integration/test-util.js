
'use strict';

const assert = require('bsert');
const {spawn} = require('child_process');
const path = require('path');
const {FullNode} = require('hsd');
const wire = require('bns/lib/wire');
const StubResolver = require('bns/lib/resolver/stub');

class TestUtil {
  constructor() {
    this.node = new FullNode({
      memory: true,
      network: 'regtest',
      listen: true,
      port: 10000,
      noDns: true,
      plugins: [require('hsd/lib/wallet/plugin')]
    });

    this.wallet = null;

    this.resolver = new StubResolver();
    this.resolver.setServers(['127.0.0.1:25349']);

    this.hnsd = null;
    this.hnsdHeight = 0;
  }

  async open() {
    await this.resolver.open();
    await this.node.open();
    await this.node.connect();

    this.wallet = this.node.plugins.walletdb;

    return this.openHNSD();
  }

  async openHNSD() {
    return new Promise((resolve, reject) => {
      this.hnsd = spawn(
        path.join(__dirname, '..', 'hnsd'),
        ['-s', '127.0.0.1:10000'],
        {stdio: 'ignore'}
      );

      this.hnsd.on('spawn', () => resolve());
      this.hnsd.on('error', () => reject());
    });
  }

  async close() {
    this.hnsd.kill('SIGKILL');
    await this.node.close();
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
