'use strict';

const crypto = require('crypto');
const { loadRequestP12, loadResponseP12 } = require('./keystore');
const { buildJwt, decodeJwt } = require('./jwt');
const { sha256Base64 } = require('./digest');
const { encryptRequest, decryptResponse } = require('./mle');

const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);

/**
 * Normalize an MLE spec to explicit `{ request, response }` booleans.
 *
 * MLE is always expressed as two independent booleans — `request` (encrypt the outgoing
 * body) and `response` (decrypt the reply) — never a clever shorthand. Missing keys fall
 * back to `base`, so a per-call spec can override just one side of the configured default.
 *
 * @param {object|undefined} spec - the supplied spec (may be partial)
 * @param {{request: boolean, response: boolean}} base - defaults for unspecified keys
 * @param {string} label - used in error messages
 * @returns {{request: boolean, response: boolean}}
 */
function normalizeMle(spec, base, label) {
  const out = { request: base.request, response: base.response };
  if (spec === undefined || spec === null) return out;
  if (typeof spec !== 'object' || Array.isArray(spec)) {
    throw new Error(`${label} must be an object like { request: boolean, response: boolean }`);
  }
  for (const key of ['request', 'response']) {
    if (key in spec) {
      if (typeof spec[key] !== 'boolean') {
        throw new Error(`${label}.${key} must be a boolean (got ${typeof spec[key]})`);
      }
      out[key] = spec[key];
    }
  }
  return out;
}

/**
 * A small, transparent Cybersource REST client.
 *
 * Configure it once with your keys, then call get/post/put/patch/delete. Each call
 * builds and signs a fresh JWT, attaches `Authorization: Bearer <jwt>`, and (optionally)
 * encrypts the request and/or decrypts the response with MLE.
 *
 * Example:
 *   const client = new CybsJwtClient({
 *     runEnvironment: 'apitest.cybersource.com',
 *     merchantId: 'my_mid',
 *     useMetaKey: true,
 *     portfolioId: 'my_portfolio_id',
 *     requestP12:  { path: 'keys/request.p12',  password: '...' },
 *     responseP12: { path: 'keys/response.p12', password: '...' },
 *   });
 *   const res = await client.post('/pts/v2/payments', payload, {
 *     mle: { request: true, response: true },
 *   });
 */
class CybsJwtClient {
  constructor(config = {}) {
    const {
      runEnvironment,
      merchantId,
      useMetaKey = false,
      portfolioId,
      requestP12,
      responseP12,
      defaultMle = { request: false, response: false },
      clientId = 'cybs-jwt-client',
    } = config;

    if (!runEnvironment) throw new Error('config.runEnvironment is required (e.g. "apitest.cybersource.com")');
    if (!merchantId) throw new Error('config.merchantId is required');
    if (useMetaKey && !portfolioId) throw new Error('config.portfolioId is required when useMetaKey is true');
    if (!requestP12 || !requestP12.path) throw new Error('config.requestP12.path is required');

    this.runEnvironment = runEnvironment;
    this.merchantId = merchantId;
    this.useMetaKey = useMetaKey;
    this.portfolioId = portfolioId;
    this.responseP12 = responseP12 || null;
    // The configured default is off on both sides; per-call options override per key.
    this.defaultMle = normalizeMle(defaultMle, { request: false, response: false }, 'config.defaultMle');
    this.clientId = clientId;

    // For meta key, identity (issuer + cert alias) is the portfolio id; otherwise the MID.
    this.keyAlias = requestP12.keyAlias || (useMetaKey ? portfolioId : merchantId);

    // Load the request p12 eagerly so config errors surface immediately.
    this.requestKeys = loadRequestP12(requestP12.path, requestP12.password, {
      keyAlias: this.keyAlias,
      mleCertAlias: requestP12.mleCertAlias,
    });

    // Response p12 is loaded lazily — only when a call actually uses response MLE.
    this._responseKeys = null;
  }

  /**
   * Resolve the effective MLE for a call: start from the configured default, then apply
   * whichever of `request` / `response` the call specified.
   */
  _resolveMle(mle) {
    return normalizeMle(mle, this.defaultMle, 'the mle option');
  }

  /** Lazily load + cache the response p12 keys. */
  _ensureResponseKeys() {
    if (this._responseKeys) return this._responseKeys;
    if (!this.responseP12 || !this.responseP12.path) {
      throw new Error('Response MLE requested but config.responseP12 was not provided');
    }
    const kidAlias = this.useMetaKey ? this.portfolioId : this.merchantId;
    this._responseKeys = loadResponseP12(this.responseP12.path, this.responseP12.password, {
      kidAlias,
      kid: this.responseP12.kid,
    });
    return this._responseKeys;
  }

  /**
   * Core request flow — returns a "glassbox" result: the answer plus a full `trace` of
   * everything that happened under the hood.
   *
   * Returns `{ ok, status, data, trace }`, where `trace` is:
   *   - `request`    — url, method, the headers actually sent, the resolved `mle` flags,
   *                    your plaintext `body`, its serialized form (`bodySerialized`), the
   *                    encrypted envelope (`bodyEncrypted`, when request MLE is on), and the
   *                    exact bytes put on the wire (`bodyWire` — what the JWT `digest` hashes).
   *   - `jwt`        — the signed compact token plus its decoded `header` and `claims`.
   *   - `encryption` — the JWE protected headers for request/response MLE (null when off).
   *   - `response`   — status, headers, the raw `{encryptedResponse}` (when response MLE),
   *                    and the final decrypted/parsed `data`.
   *
   * The trace is always built and is intentionally lossless — it includes plaintext PANs,
   * the bearer JWT, etc. This is a glassbox dev/troubleshooting tool, not a production
   * client. If a crypto step throws, the partial trace is attached as `err.trace`.
   */
  async request(method, path, body, opts = {}) {
    method = method.toUpperCase();
    const mle = this._resolveMle(opts.mle);
    const hasBody = body !== undefined && body !== null;

    // Build the trace incrementally so that, if a step throws (e.g. encrypt/decrypt), we can
    // attach whatever we've learned so far to the error — see the catch at the end.
    const trace = {
      request: {
        url: `https://${this.runEnvironment}${path}`,
        method,
        headers: null,
        mle,
        body: hasBody ? body : null,
        bodySerialized: null,
        bodyEncrypted: null,
        bodyWire: null,
      },
      jwt: null,
      encryption: { request: null, response: null },
      response: null,
    };

    try {
      // 1. Serialize the body and (if request MLE) encrypt it first — the digest must cover
      //    the exact bytes we send, so encryption happens before digesting.
      let bodyString;
      if (hasBody) {
        const plaintext = JSON.stringify(body);
        trace.request.bodySerialized = plaintext;

        let outbound = body;
        if (mle.request) {
          const { encryptedRequest, protectedHeader } = await encryptRequest(plaintext, {
            cert: this.requestKeys.mleCert,
            mleSerial: this.requestKeys.mleSerial,
          });
          outbound = { encryptedRequest };
          trace.request.bodyEncrypted = outbound;
          trace.encryption.request = protectedHeader;
        }
        bodyString = JSON.stringify(outbound);
        trace.request.bodyWire = bodyString;
      }

      // 2. Build the claim set.
      const nowSec = Math.floor(Date.now() / 1000);
      const claims = {
        iat: nowSec,
        exp: nowSec + 120, // tokens are short-lived: 2 minutes
        'request-host': this.runEnvironment,
        'request-resource-path': path,
        'request-method': method.toLowerCase(),
        iss: this.useMetaKey ? this.portfolioId : this.merchantId,
        jti: crypto.randomUUID(),
        'v-c-jwt-version': '2',
      };
      if (this.merchantId != null) claims['v-c-merchant-id'] = this.merchantId;

      // Body-bearing methods carry a digest of the (possibly encrypted) payload.
      if (BODY_METHODS.has(method) && bodyString != null) {
        claims['digest'] = sha256Base64(bodyString);
        claims['digest-algorithm'] = 'SHA-256';
      }

      // Asking the server to encrypt the response: tell it which key to encrypt to.
      if (mle.response) {
        claims['v-c-response-mle-kid'] = this._ensureResponseKeys().responseMleKid;
      }

      // 3. Sign it. Decode our own token straight back into the trace so the header/claims
      //    shown are literally what the signed token carries.
      const jwt = buildJwt(claims, { kid: this.requestKeys.signingSerial }, this.requestKeys.privateKeyPem);
      const decoded = decodeJwt(jwt);
      trace.jwt = { compact: jwt, header: decoded.header, claims: decoded.payload };

      // 4. Send it. For JWT auth the ONLY auth header is Authorization: Bearer <jwt>.
      const url = trace.request.url;
      const headers = {
        Authorization: `Bearer ${jwt}`,
        'v-c-client-id': this.clientId,
        'User-Agent': this.clientId,
        Accept: 'application/json',
      };
      if (bodyString != null) headers['Content-Type'] = 'application/json';
      trace.request.headers = headers;

      const res = await fetch(url, { method, headers, body: bodyString });

      // 5. Parse, and decrypt the response if it came back encrypted.
      const text = await res.text();
      let data = null;
      if (text) {
        try {
          data = JSON.parse(text);
        } catch {
          data = text; // non-JSON error pages, etc.
        }
      }

      trace.response = {
        status: res.status,
        headers: Object.fromEntries(res.headers),
        encrypted: null,
        data: null,
      };

      if (mle.response && data && typeof data === 'object' && data.encryptedResponse) {
        trace.response.encrypted = { encryptedResponse: data.encryptedResponse };
        const decrypted = await decryptResponse(
          data.encryptedResponse,
          this._ensureResponseKeys().responsePrivateKeyPem
        );
        data = decrypted.data;
        trace.encryption.response = decrypted.protectedHeader;
      }
      trace.response.data = data;

      return { ok: res.ok, status: res.status, data, trace };
    } catch (err) {
      if (!err.trace) err.trace = trace;
      throw err;
    }
  }

  get(path, opts) {
    return this.request('GET', path, undefined, opts);
  }

  delete(path, opts) {
    return this.request('DELETE', path, undefined, opts);
  }

  post(path, body, opts) {
    return this.request('POST', path, body, opts);
  }

  put(path, body, opts) {
    return this.request('PUT', path, body, opts);
  }

  patch(path, body, opts) {
    return this.request('PATCH', path, body, opts);
  }
}

module.exports = { CybsJwtClient };
