'use strict';

const crypto = require('crypto');

/**
 * Hand-rolled JWT (RS256) signing and decoding.
 *
 * The whole point of this module is to be *readable*. A JWT is just three
 * base64url-encoded parts joined by dots:
 *
 *     base64url(header) . base64url(payload) . base64url(signature)
 *
 * The signature is computed over the first two parts ("the signing input") using
 * the RSA private key. Cybersource verifies it with the public key tied to the
 * `kid` (key id) in the header — which is your certificate's serial number.
 *
 * No JWT library is used here on purpose: every step is visible so you can see
 * exactly what gets signed and debug it when an auth call fails.
 */

/**
 * base64url encoding (RFC 7515): standard base64, but `+`→`-`, `/`→`_`, no `=` padding.
 * @param {Buffer|string} input
 * @returns {string}
 */
function base64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Reverse of base64url, returning a Buffer.
 * @param {string} str
 * @returns {Buffer}
 */
function base64urlDecode(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(padded, 'base64');
}

/**
 * Build and sign a Cybersource JWT.
 *
 * @param {object} payload - the claim set (iat, exp, iss, request-*, digest, etc.)
 * @param {object} options
 * @param {string} options.kid - key id for the header (your cert serial number)
 * @param {string} privateKeyPem - RSA private key in PEM format
 * @returns {string} the compact JWT (header.payload.signature)
 */
function buildJwt(payload, { kid }, privateKeyPem) {
  // 1. The header declares the algorithm and which key signed it.
  const header = { typ: 'JWT', alg: 'RS256', kid };

  // 2. base64url the header and payload, join with a dot. THIS is what gets signed.
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  // 3. Sign the signing input with RSA-SHA256 (RS256) using the private key.
  const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput, 'utf8'), privateKeyPem);
  const encodedSignature = base64url(signature);

  // 4. The JWT is the signing input plus the signature, dot-joined.
  return `${signingInput}.${encodedSignature}`;
}

/**
 * Decode a JWT *without* verifying its signature — for inspection/troubleshooting.
 * Use this to eyeball the claims when a call returns 401.
 *
 * @param {string} token
 * @returns {{header: object, payload: object, signature: string}}
 */
function decodeJwt(token) {
  const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
  return {
    header: JSON.parse(base64urlDecode(encodedHeader).toString('utf8')),
    payload: JSON.parse(base64urlDecode(encodedPayload).toString('utf8')),
    signature: encodedSignature,
  };
}

module.exports = { buildJwt, decodeJwt, base64url, base64urlDecode };
