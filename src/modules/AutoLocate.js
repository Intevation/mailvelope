/**
 * Copyright (C) 2018 Intevation GmbH
 * Licensed under the GNU Affero General Public License version 3
 */


import KeyServer from './keyserver';
import {prefs} from './prefs';
import {getById as getKeyringById} from './keyring';
import mvelo from '../lib/lib-mvelo';
import WKDLocate from './WKDLocate';

/**
 * @fileOverview This file implements a bridge for automated lookup
 * of keys from other sources. E.g. the Mailvelope Keyserver and
 * Web Key Directories.
 */

export default class AutoLocate {
  constructor() {
    this.keyserver = new KeyServer();
    this.wkd = new WKDLocate();
  }

  /**
   * Get a verified public key from autolocate sources by either email address,
   * key id, or fingerprint.
   *
   * @param {string} options.email         (optional) The user id's email address
   * @param {string} options.keyId         (optional) The long 16 char key id
   * @param {string} options.fingerprint   (optional) The 40 char v4 fingerprint
   */
  async locate(options) {
    let armored;
    if (this.getKeyserverEnabled()) {
      try {
        const key = await this.keyserver.lookup(options);
        if (key) {
          armored = key.publicKeyArmored;
        }
      } catch (e) {
        // Failures are not critical so we only info log them.
        console.log(`Mailvelope Server: Did not find key (Errors are expected): ${e}`);
      }
    }
    if (!armored && options.email && this.getWKDEnabled()) {
      // As we do not (yet) handle key updates through WKD we only want one
      // one key.
      try {
        armored = await this.wkd.lookup(options.email, true);
      } catch (e) {
        // WKD Failures are not critical so we only info log them.
        console.log(`WKD: Did not find key (Errors are expected): ${e}`);
      }
    }
    if (armored) {
      // persist key in main keyring
      const localKeyring = getKeyringById(mvelo.MAIN_KEYRING_ID);
      console.log(`Importing \n${armored}`);
      await localKeyring.importKeys([{type: 'public', armored}]);
    }
    return;
  }

  /**
   * Check if WKD lookup is enabled.
   *
   * @return {Boolean}
   */
  getWKDEnabled() {
    return prefs.keyserver.wkd_lookup === true;
  }

  /**
   * Check if the Mailvelope Keyserver is enabled.
   *
   * @return {Boolean}
   */
  getKeyserverEnabled() {
    return prefs.keyserver.mvelo_tofu_lookup === true;
  }

  /**
   * Check if any source is enabled.
   *
   * @return {Boolean}
   */
  getEnabled() {
    return this.getWKDEnabled() || this.getKeyserverEnabled();
  }
}
