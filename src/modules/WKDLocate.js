/**
 * Copyright (C) 2018 Intevation GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

/**
 * @fileOverview This file implements Web Key directory lookup.
 */

import * as crypto from 'crypto';
import {prefs} from './prefs';
import * as openpgp from 'openpgp';
import {mapKeyUserIds} from './key';

// For testing the following publicly available userIds can be used:
//
// test-large-rsa@testkolab.intevation.de        A large > 1MiB ECC key.
// test-multikey-rsa@testkolab.intevation.de     Multiple keys, one is revoked, two are valid, one does not match the UID
// test-not-matching-rsa@testkolab.intevation.de A key without a matching UID
// test-multi-uids-rsa@testkolab.intevation.de   A key with multiple UIDs
//
// By leaving of the -rsa suffix you can obtain ECC variants of the keys.


/**
 * Encode input buffer using Z-Base32 encoding.
 * See: https://tools.ietf.org/html/rfc6189#section-5.1.6
 *
 * Code copied from openpgp.js src/util.js rev. 22c66c1
 * under the terms of the GNU Lesser General Public License Version 3
 *
 * Can be replaced by openpgp.util.encodeZBase32 after updating openpgpjs.
 *
 * @param {Uint8Array} data The binary data to encode
 * @returns {String} Binary data encoded using Z-Base32
 */
function encodeZBase32(data) {
  if (data.length === 0) {
    return "";
  }
  const ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";
  const SHIFT = 5;
  const MASK = 31;
  let buffer = data[0];
  let index = 1;
  let bitsLeft = 8;
  let result = '';
  while (bitsLeft > 0 || index < data.length) {
    if (bitsLeft < SHIFT) {
      if (index < data.length) {
        buffer <<= 8;
        buffer |= data[index++] & 0xff;
        bitsLeft += 8;
      } else {
        const pad = SHIFT - bitsLeft;
        buffer <<= pad;
        bitsLeft += pad;
      }
    }
    bitsLeft -= SHIFT;
    result += ALPHABET[MASK & (buffer >> bitsLeft)];
  }
  return result;
}

/**
 * Build a WKD Url from a canonicalized email (mbox) address.
 *
 * Code based on openpgp.js src/util.js rev. 22c66c1
 * under the terms of the GNU Lesser General Public License Version 3
 *
 * @param {String]   email   The canonicalized RFC822 addr spec.
 *
 * @returns {String} The WKD URL according to draft-koch-openpgp-webkey-service-06
 */
function buildWKDUrl(email) {
  const [, localPart, domain] = /(.*)@(.*)/.exec(email);

  if (!localPart || !domain) {
    throw new Error(`WKD: failed to parse: ${email}`);
  }
  const shasum = crypto.createHash('sha1');
  shasum.update(localPart.toLowerCase());
  const digest = shasum.digest();
  const localEncoded = encodeZBase32(digest);

  return `https://${domain}/.well-known/openpgpkey/hu/${localEncoded}`;
}

/** Convert a promise into a promise with a timeout.
  *
  * @param ms       The timeout in milliseconds.
  * @param promise  The promise to wrap.
  *
  * @returns {Promise} A promise with a timeout.
  **/
function timeout(ms, promise) {
  return new Promise(((resolve, reject) => {
    setTimeout(() => {
      reject(new Error("WKD: Timeout"));
    }, ms);
    promise.then(resolve, reject);
  }));
}

/**
 * A WKD key can contain UserIDs which do not match what
 * was searched for. This function inspects the response and
 * filters out UserIDs and keys which do not match, before returning
 * the keys from the response in armored format to be imported
 * into the keyring.
 *
 * Security: This is a central element for trust by https / WKD through
 * the domain provider. If accepting any key or any userid provided, there
 * would be no trust gain as a malicious domain could pollute the keyring
 * or include userids for other domains.  The validity check and onlyOne
 * API make this function more convenient to use for simple implementations which
 * do not plan to use WKD for Key rollover but have no security purpose.
 *
 * @param {ByteArray}               Binary data that might contain keys
 * @param {String} email            The email address for the userids
 * @param {Boolean} onlyOne         Return only the best key. Best means: The newest, valid key.
 *                                  If no keys are valid it only returns the newest.
 * @returns {Array[String]}|String  An array of the ASCII armored filtered keys or only one armored key.
 */
function parseKeysForEMail(data, email, onlyOne) {
  if (!openpgp.util.isUint8Array(data)) {
    throw new Error(`WKD: parseKeysForEMail invalid data type ${data.constructor.toString()}`);
  }

  const result = openpgp.key.read(data);
  if (result.err) {
    throw new Error(`WKD: Failed to parse result for '${email}': ${result.err}`);
  }

  try {
    const keptArmoredKeys = new Array;
    let candidate;
    result.keys.forEach(key => {
      const keptUsers = new Array;
      console.log(`WKD: inspecting: ${key.primaryKey.getFingerprint()}`);
      key.users.forEach(user => {
        // This looks a bit weird but we should use the same function to validate
        // mail addresses as other code.
        const userMapped = {userId: user.userId.userid};
        mapKeyUserIds(userMapped);
        if (userMapped.email.toLowerCase() === email.toLowerCase()) {
          keptUsers.push(user);
        } else {
          console.log(`WKD: skipping not matching userid: '${user.userId.userid}'`);
        }
      });
      if (keptUsers.length) {
        key.users = keptUsers;
        if (onlyOne) {
          if (!candidate) {
            candidate = key;
          } else { // More then one key in WKD is a rare case. Example can be found as "test-multikey@testkolab.intevation.de"
            const newValid = key.verifyPrimaryKey() === openpgp.enums.keyStatus.valid;
            const oldValid = candidate.verifyPrimaryKey() === openpgp.enums.keyStatus.valid;
            // Prefer the one that is valid
            if (newValid && !oldValid) {
              candidate = key;
              console.log(`WKD: Preferring ${key.primaryKey.getFingerprint()} over ${candidate.primaryKey.getFingerprint()} because of validity.`);
            } else if (newValid === oldValid && key.primaryKey.created > candidate.primaryKey.created) {
              // If both are valid or invalid check the creation date
              console.log(`WKD: Preferring ${key.primaryKey.getFingerprint()} over ${candidate.primaryKey.getFingerprint()} because of cr date of primary.`);
              candidate = key;
            }
          }
        } else {
          keptArmoredKeys.push(key.armor());
        }
      } else {
        // Example for this can be found as "test-not-matching@testkolab.intevation.de"
        console.log(`WKD: skipping not matching key '${key.primaryKey.getFingerprint()}' (bad server)`);
      }
    });
    if (onlyOne && candidate) {
      return candidate.armor();
    }
    if (keptArmoredKeys.length) {
      return keptArmoredKeys;
    }
    throw new Error("WKD: Failed to parse any matching key from the result (bad server)");
  } catch (e) {
    throw new Error(`WKD: Error handling keys: '${e}'`);
  }
}

/** Adds a size limit on a Response which throws
 * an error if the limit is surpassed.
 *
 * Based on: https://fetch.spec.whatwg.org/
 *
 * @param {Response} response       The fetch response
 * @param {Number}   limit          The maximum bytes to read
 *
 * @returns {Uint8array}   Array containing the data read.
 */
function sizeLimitResponse(response, limit) {
  if (response.status != 200) {
    throw new Error(`WKD: Invalid WKD Response ${response.status}:${response.statusText}`);
  }

  const reader = response.body.getReader();
  let total = 0;
  const results = new Array;
  return pump();
  function pump() {
    return reader.read().then(({done, value}) => {
      if (done) {
        return openpgp.util.concatUint8Array(results);
      }
      total += value.byteLength;
      results.push(new Uint8Array(value));
      if (total > limit) {
        // Example for this can be found as "test-large@testkolab.intevation.de"
        throw new Error("WKD: Response longer then the max size");
      }
      return pump();
    });
  }
}

export default class WKDLocate {
  constructor() {
    this.blacklist = prefs.keyserver.wkd_blacklist || [];
    this.TIMEOUT = 5; // Fetch timeout in seconds (based on GnuPG)
    this.SIZE_LIMIT = 64; // Size limit of the response in KiB (based on GnuPG)
    // TODO implement last checked check / database.
  }

  /**
   * Get a key from WKD by the email address.
   * @param {String} email           The keys email address
   * @param {Boolean} onlyOne        Return only one key instead of an Array.
   * @yield {Array[String]}|String   Array of armored keys with matching uids
   */
  async lookup(email, onlyOne) {
    if (!email) {
      throw new Error("WKD: Skipping lookup without email.");
    }

    const [, domain] = /.*@(.*)/.exec(email);

    this.blacklist.forEach(item => {
      if (item.toLowerCase() == domain.toLowerCase()) {
        throw new Error("WKD: Skipping blacklisted domain.");
      }
    });

    const url = buildWKDUrl(email);
    console.log(`WKD: Fetching URL: ${url}`);

    // Impose a size limit and timeout similar to that of gnupg.
    const data = await timeout(this.TIMEOUT * 1000, window.fetch(url)).then(
      res => sizeLimitResponse(res, this.SIZE_LIMIT * 1024));

    // Now we should have binary keys in the response.
    const armored = parseKeysForEMail(data, email, onlyOne);

    return armored;
  }
}
