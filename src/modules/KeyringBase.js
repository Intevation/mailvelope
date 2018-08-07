/**
 * Copyright (C) 2018 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

import mvelo from '../lib/lib-mvelo';
import * as openpgp from 'openpgp';
import {goog} from './closure-library/closure/goog/emailaddress';
import {getKeyringAttr} from './keyring';
import {mapKeys, mapSubKeys, mapUsers, mapKeyUserIds, getUserId, isValidEncryptionKey, sortKeysByCreationDate} from './key';
import * as trustKey from './trustKey';
import KeyServer from './keyserver';

const keyServer = new KeyServer();

export default class KeyringBase {
  constructor(keyringId, keyStore) {
    this.id = keyringId;
    this.keystore = keyStore;
  }

  getKeys() {
    // map keys to UI format
    let keys = this.getPublicKeys().concat(this.getPrivateKeys());
    // sort by key type and name
    keys = keys.sort((a, b) => {
      const compType = a.type.localeCompare(b.type);
      if (compType === 0) {
        return a.name.localeCompare(b.name);
      } else {
        return compType;
      }
    });
    return keys;
  }

  getPublicKeys() {
    return mapKeys(this.keystore.publicKeys.keys);
  }

  getPrivateKeys() {
    return mapKeys(this.keystore.privateKeys.keys);
  }

  /**
   * Check if keyring has any private key or specific private keys by keyId
   * @param  {Array<openpgp.Keyid|String>}  keyIds or fingerprints
   * @return {Boolean}
   */
  hasPrivateKey(keyIds) {
    if (!keyIds) {
      return Boolean(this.keystore.privateKeys.keys.length);
    }
    return keyIds.some(keyId => this.keystore.privateKeys.getForId(typeof keyId === 'string' ? keyId : keyId.toHex(), true));
  }

  getValidSigningKeys() {
    return mapKeys(this.keystore.privateKeys.keys.filter(key => this.validateDefaultKey(key)))
    .sort((a, b) => a.name.localeCompare(b.name));
  }

  getKeyDetails(fingerprint) {
    const details = {};
    const keys = this.keystore.getKeysForId(fingerprint);
    if (keys) {
      const key = keys[0];
      // subkeys
      mapSubKeys(key.subKeys, details);
      // users
      mapUsers(key.users, details, this.keystore, key.primaryKey);
      // key is valid default key
      details.validDefaultKey = this.validateDefaultKey(key);
      return details;
    } else {
      throw new Error('Key with this fingerprint not found: ', fingerprint);
    }
  }

  /**
   * Get the following data for all keys: user id, key id, fingerprint, email and name
   * @param {Boolean} [options.allUsers] return separate entry for all user ids of key
   * @return {Array<Object>} list of key meta data objects in the form {key, keyId, fingerprint, users}
   */
  getKeyData(options = {}) {
    const result = [];
    for (const key of this.keystore.getAllKeys()) {
      if (key.verifyPrimaryKey() === openpgp.enums.keyStatus.invalid ||
          trustKey.isKeyPseudoRevoked(this.id, key)) {
        continue;
      }
      const keyData = {};
      keyData.key = key;
      keyData.keyId = key.primaryKey.getKeyId().toHex().toUpperCase();
      keyData.fingerprint = key.primaryKey.getFingerprint();
      if (options.allUsers) {
        // consider all user ids of key
        keyData.users = [];
        for (const keyUser of key.users) {
          if (keyUser.userId && keyUser.verify(key.primaryKey) === openpgp.enums.keyStatus.valid) {
            const user = {userId: keyUser.userId.userid};
            // check for duplicates
            if (keyData.users.some(existingUser => existingUser.userId === user.userId)) {
              continue;
            }
            mapKeyUserIds(user);
            // check for valid email address
            if (!user.email) {
              continue;
            }
            keyData.users.push(user);
          }
        }
      } else {
        // only consider primary user
        const user = {userId: getUserId(key)};
        mapKeyUserIds(user);
        keyData.users = [user];
      }
      result.push(keyData);
    }
    return result;
  }

  /**
   * Query keys by email address
   * @param  {Array<String>} emailAddr
   * @param  {Object} [options.pub = true] - query for public keys
   * @param  {Object} [options.priv = true] - query for private keys
   * @param  {Object} [options.sort = false] - sort results by key creation date and default key status
   * @param  {Object} [options.valid = true] - result keys are verified
   * @return {Object} - map in the form {address: [key1, key2, ..]}
   */
  getKeyByAddress(emailAddr, {pub = true, priv = true, sort = false, valid = true} = {}) {
    const result = Object.create(null);
    const emailArray = mvelo.util.toArray(emailAddr);
    for (const email of emailArray) {
      result[email] = [];
      if (pub) {
        result[email] = result[email].concat(this.keystore.publicKeys.getForAddress(email));
      }
      if (priv) {
        result[email] = result[email].concat(this.keystore.privateKeys.getForAddress(email));
      }
      if (valid) {
        result[email] = result[email].filter(key => isValidEncryptionKey(key, this.id));
      }
      if (!result[email].length) {
        result[email] = false;
      } else if (sort) {
        // sort by key creation date and default key status
        const defaultKeyFpr = this.getDefaultKeyFpr();
        sortKeysByCreationDate(result[email], defaultKeyFpr);
      }
    }
    return result;
  }

  /**
   * Get armored keys by fingerprints
   * @param  {Array<String>|String} keyFprs
   * @param  {Boolean} options.all - return all keys in the keyring
   * @param  {Boolean} options.pub - return all keys as public armored
   * @param  {Boolean} options.pub - return all private keys as private armored
   * @return {Array<Strin>}
   */
  getArmoredKeys(keyFprs, options) {
    const result = [];
    keyFprs = mvelo.util.toArray(keyFprs);
    let keys = null;
    if (options.all) {
      keys = this.keystore.getAllKeys();
    } else {
      keys = keyFprs.map(keyFpr => this.keystore.getKeysForId(keyFpr)[0]);
    }
    keys.forEach(key => {
      const armored = {};
      if (options.pub) {
        armored.armoredPublic = key.toPublic().armor();
      }
      if (options.priv && key.isPrivate()) {
        armored.armoredPrivate = key.armor();
      }
      result.push(armored);
    });
    return result;
  }

  hasDefaultKey() {
    return Boolean(this.keystore.getDefaultKeyFpr());
  }

  setDefaultKey(fpr) {
    return this.keystore.setDefaultKey(fpr);
  }

  validateDefaultKey(defaultKey) {
    return defaultKey.verifyPrimaryKey() === openpgp.enums.keyStatus.valid &&
           defaultKey.getEncryptionKeyPacket() &&
           defaultKey.getSigningKeyPacket() &&
           !trustKey.isKeyPseudoRevoked(this.id, defaultKey);
  }

  getPrivateKeyByFpr(keyFpr) {
    return this.keystore.privateKeys.getForId(keyFpr);
  }

  /**
   * Return first private key that matches keyIds
   * @param  {Array<openpgp.Keyid|String>|openpgp.Keyid|String} keyIds - keyIds or fingerprints
   * @return {openpgp.key.Key|null}
   */
  getPrivateKeyByIds(keyIds) {
    keyIds = mvelo.util.toArray(keyIds);
    for (const keyId of keyIds) {
      const keyIdHex = typeof keyId === 'string' ? keyId : keyId.toHex();
      const key = this.keystore.privateKeys.getForId(keyIdHex, true);
      if (key) {
        return key;
      }
    }
    return null;
  }

  /**
   * Get keys by fingerprints
   * @param  {Array<String>} keyFprs
   * @return {Array<openpgp.key.Key>}
   */
  getKeysByFprs(keyFprs) {
    return keyFprs.map(keyFpr => {
      const keyArray = this.keystore.getKeysForId(keyFpr);
      if (keyArray) {
        return keyArray[0];
      }
      throw new mvelo.Error(`No key found for ID ${keyFpr}`, 'NO_KEY_FOUND_FOR_ENCRYPTION');
    });
  }

  /**
   * Find key or sub key packet by keyId and return fingerprint
   * @param  {String} keyId
   * @return {String}
   */
  getFprForKeyId(keyId) {
    const keyArray = this.keystore.getKeysForId(keyId, true);
    if (!keyArray) {
      throw new mvelo.Error(`No key found for ID ${keyId}`, 'NO_KEY_FOUND_FOR_ID');
    }
    if (keyArray.length > 1) {
      throw new mvelo.Error(`Collision of long key ID ${keyId}, more than one key found in keyring`, 'LONG_KEY_ID_COLLISION');
    }
    const keyPacket = keyArray[0].getKeyPacket([openpgp.Keyid.fromId(keyId)]);
    return keyPacket.getFingerprint();
  }

  getAttributes() {
    return getKeyringAttr(this.id);
  }

  removeKey(fingerprint, type) {
    let removedKey;
    if (type === 'public') {
      removedKey = this.keystore.publicKeys.removeForId(fingerprint);
    } else if (type === 'private') {
      removedKey = this.keystore.privateKeys.removeForId(fingerprint);
    }
    if (!removedKey) {
      throw new Error('removeKey: key not found');
    }
    return removedKey;
  }

  /**
   * Generate a new PGP keypair and optionally upload the public key to the
   * key server.
   * @param {number} options.numBits - the keysize in bits
   * @param {Array} options.userIds - email addresses and names
   * @param {string} options.passphrase - to protect the private key on disk
   * @param {boolean} options.uploadPublicKey - if upload to key server is desired
   * @param {Number} options.keyExpirationTime - the number of seconds after the key creation time that the key expires
   * @param {Boolean} options.unlocked - returned secret part of the generated key is unlocked
   * @yield {Object} - the generated key pair
   */
  async generateKey({numBits, userIds, passphrase, uploadPublicKey, keyExpirationTime, unlocked = false}) {
    userIds = userIds.map(userId => {
      if (userId.fullName) {
        return (new goog.format.EmailAddress(userId.email, userId.fullName)).toString();
      } else {
        return `<${userId.email}>`;
      }
    });
    const newKey = await this.keystore.generateKey({userIds, passphrase, numBits: parseInt(numBits), keyExpirationTime, unlocked});
    this.keystore.privateKeys.push(newKey.key);
    // upload public key
    if (uploadPublicKey) {
      await keyServer.upload({publicKeyArmored: newKey.publicKeyArmored});
    }
    return newKey;
  }
}