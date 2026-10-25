'use strict';

const { SignJWT, decodeJwt: decodePayload, decodeProtectedHeader } = require('jose');

/**
 * JWT signing (RS256 or HMAC) and decoding, via `jose`.
 *
 * A JWT is three base64url-encoded parts joined by dots:
 *
 *     base64url(header) . base64url(payload) . base64url(signature)
 *
 * The signature covers the first two parts. Cybersource supports two ways to produce it:
 *
 *   - Certificate (RS256): sign with the RSA private key from your p12. Cybersource
 *     verifies with the public key tied to the `kid` — your certificate's serial number.
 *   - Shared secret (HS256/384/512): an HMAC keyed with the secret from Business Center.
 *     Cybersource holds the same secret and recomputes the HMAC. The `kid` is the shared
 *     secret's key id.
 *
 * Everything else about the token (header shape, claims, encoding) is identical. `jose`
 * does the encoding and signing; the values that matter to Cybersource (`alg`, `kid`,
 * and the claim set) are all set explicitly by the caller.
 */

/** HMAC algorithms Cybersource accepts for shared-secret JWTs. */
const HMAC_ALGS = { HS256: true, HS384: true, HS512: true };

/**
 * Build and sign a Cybersource JWT.
 *
 * @param {object} payload - the claim set (iat, exp, iss, request-*, digest, etc.)
 * @param {object} options
 * @param {string} options.kid - key id for the header (cert serial number, or shared secret key id)
 * @param {string} [options.alg='RS256'] - 'RS256', or 'HS256' / 'HS384' / 'HS512' for a shared secret
 * @param {import('crypto').KeyObject|Uint8Array} key - RSA private key for RS256; the raw secret bytes for HMAC
 * @returns {Promise<string>} the compact JWT (header.payload.signature)
 */
function buildJwt(payload, { kid, alg = 'RS256' }, key) {
  if (alg !== 'RS256' && !HMAC_ALGS[alg]) {
    throw new Error(`Unsupported JWT alg "${alg}" (expected RS256, HS256, HS384, or HS512)`);
  }
  // The claims (including iat/exp) are set by the caller, so no jose claim helpers here.
  return new SignJWT(payload).setProtectedHeader({ typ: 'JWT', alg, kid }).sign(key);
}

/**
 * Decode a JWT *without* verifying its signature — for inspection/troubleshooting.
 * Use this to eyeball the claims when a call returns 401.
 *
 * @param {string} token
 * @returns {{header: object, payload: object, signature: string}}
 */
function decodeJwt(token) {
  return {
    header: decodeProtectedHeader(token),
    payload: decodePayload(token),
    signature: token.split('.')[2],
  };
}

/**
 * Turn the shared secret shown in Business Center into the bytes used as the HMAC key.
 *
 * Cybersource displays the secret base64-encoded; its signing examples decode it
 * (`base64 -d`) before computing the HMAC. Using the base64 *text* as the key instead is
 * the classic shared-secret 401: the token looks perfect but the signature never matches.
 *
 * @param {string} secret - the base64 secret as shown in Business Center
 * @returns {Buffer}
 */
function decodeSharedSecret(secret) {
  const trimmed = String(secret).trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
    throw new Error('sharedSecret.secret must be the base64 value shown in Business Center');
  }
  return Buffer.from(trimmed, 'base64');
}

module.exports = { buildJwt, decodeJwt, decodeSharedSecret, HMAC_ALGS };
