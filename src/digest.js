'use strict';

const crypto = require('crypto');

/**
 * Cybersource's JWT auth carries a SHA-256 digest of the request body *inside* the
 * signed token (the `digest` claim) for POST/PUT/PATCH. This is how the server knows
 * the body wasn't tampered with after you signed it.
 *
 * The digest MUST be computed over the exact bytes that go out on the wire. If you
 * encrypt the body (request MLE), digest the encrypted `{encryptedRequest:...}`
 * envelope — not the original plaintext.
 *
 * @param {string} bodyString - the exact request body string being sent
 * @returns {string} base64-encoded SHA-256 hash
 */
function sha256Base64(bodyString) {
  return crypto.createHash('sha256').update(Buffer.from(bodyString, 'utf8')).digest('base64');
}

module.exports = { sha256Base64 };
