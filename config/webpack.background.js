/* eslint strict: 0 */
'use strict';

const path = require('path');
const common = require('./webpack.common');
const pjson = require('../package.json');

const entry = './src/background.js';
const output = {
  path: path.resolve('./build/tmp'),
  pathinfo: true,
  filename: 'background.bundle.js'
};
const resolve = {
  modules: ["node_modules"],
  alias: {
    'mailreader-parser': path.resolve('./node_modules/mailreader/src/mailreader-parser'),
    'emailjs-stringencoding': path.resolve('./src/lib/emailjs-stringencoding')
  }
};

const prod = {...common.prod,
  entry,
  output,
  resolve,
  module: {
    rules: [common.replaceVersion(/defaults\.json$/, pjson.version)],
    noParse: /openpgp\.js$/
  }
};

const dev = {...prod,
  mode: 'development',
  devtool: 'cheap-module-source-map',
  module: {
    rules: [common.replaceVersion(/defaults\.json$/, `${pjson.version} build: ${(new Date()).toISOString().slice(0, 19)}`)],
    noParse: /openpgp\.js$/
  }
};

module.exports = [dev];

module.exports.prod = prod;
module.exports.dev = dev;
