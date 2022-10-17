
'use strict';

const {spawn} = require('child_process');
const path = require('path');
const {FullNode} = require('hsd');
const dns = require('bns/lib/dns');

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

    this.resolver = new dns.Resolver({
      host: '127.0.0.1',
      port: 25349,
      dnssec: true
    });
    this.resolver.setServers(['127.0.0.1:25349']);

    this.hnsd = null;
    this.hnsdHeight = 0;
  }

  async open() {
    await this.node.open();
    await this.node.connect();

    this.wallet = this.node.plugins.walletdb;

    this.hnsd = spawn(
      path.join(__dirname, '..', 'hnsd'),
      ['-s', '127.0.0.1:10000']
    );

    this.hnsd.stdout.on('data', (data) => {
      // TODO: `data` is always 8192 bytes and output gets cut off, why?
      const chunk = data.toString('ascii');
      const lines = chunk.split(/\n/);

      for (const line of lines) {
        const words = line.split(/\s+/);

        if (words[0] !== 'chain' || words.length < 2)
          continue;

        this.hnsdHeight = parseInt(words[1].slice(1, -2));
      }
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

  waitForSync() {
    return new Promise((resolve, reject) => {
      // Hack
      setTimeout(() => {
        resolve();
      }, 5000);

    // // TODO: Fix hnsd stdout parsing for chain height
    //   setTimeout(() => {
    //     reject(new Error('Timeout waiting for sync'));
    //   }, 5000);
    //   setInterval(() => {
    //     if (this.hnsdHeight === this.node.chain.height)
    //       resolve();
    //   }, 100);
    });
  }
}

module.exports = TestUtil;
