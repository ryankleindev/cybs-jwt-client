'use strict';

const crypto = require('crypto');
const forge = require('node-forge');
const { CompactEncrypt, compactDecrypt } = require('jose');

/**
 * Message-Level Encryption (MLE).
 *
 * Unlike the JWT signing (which we hand-roll to teach it), the JWE encryption here uses
 * the `jose` library — the same one the official SDK uses. JWE (RSA-OAEP-256 key wrap +
 * A256GCM content encryption) is genuinely intricate and not worth hand-rolling; the
 * teaching focus is the auth/JWT flow, not reimplementing AES-GCM.
 *
 * Two directions, two *different* keys:
 *   - Request MLE:  encrypt the body TO Cybersource using their PUBLIC cert.
 *   - Response MLE: decrypt the response using YOUR response PRIVATE key.
 */

/**
 * Encrypt a request body into the `{ encryptedRequest }` envelope Cybersource expects.
 *
 * @param {string} jsonString - the plaintext JSON body (exact string)
 * @param {object} args
 * @param {object} args.cert      - the Cybersource request-MLE cert (node-forge cert)
 * @param {string} args.mleSerial - that cert's serial number (becomes the JWE `kid`)
 * @returns {Promise<{encryptedRequest: string}>}
 */
async function encryptRequest(jsonString, { cert, mleSerial }) {
  if (!cert) {
    throw new Error(
      'Request MLE requested but no MLE certificate was loaded. Ensure the request p12 ' +
        'contains the Cybersource cert (CN=CyberSource_SJC_US) or set requestP12.mleCertAlias.'
    );
  }

  // Convert the forge cert -> PEM -> a Node public KeyObject jose can use.
  const publicKey = crypto.createPublicKey(forge.pki.certificateToPem(cert));

  const protectedHeader = {
    alg: 'RSA-OAEP-256', // how the random content key is wrapped (to Cybersource's RSA key)
    enc: 'A256GCM', // how the payload itself is encrypted
    cty: 'JWT',
    kid: mleSerial, // tells Cybersource which of their keys you encrypted to
    iat: Math.floor(Date.now() / 1000),
  };

  const token = await new CompactEncrypt(Buffer.from(jsonString, 'utf8'))
    .setProtectedHeader(protectedHeader)
    .encrypt(publicKey);

  return { encryptedRequest: token };
}

/**
 * Decrypt a `{ encryptedResponse }` envelope back into a parsed object.
 *
 * @param {string} jwe - the compact JWE string from `data.encryptedResponse`
 * @param {string} responsePrivateKeyPem - YOUR response-MLE private key (PEM)
 * @returns {Promise<object>}
 */
async function decryptResponse(jwe, responsePrivateKeyPem) {
  const privateKey = crypto.createPrivateKey(responsePrivateKeyPem);
  const { plaintext } = await compactDecrypt(jwe, privateKey);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

module.exports = { encryptRequest, decryptResponse };
