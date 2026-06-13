'use strict';

const crypto = require('crypto');
const { loadRequestP12, loadResponseP12 } = require('./keystore');
const { buildJwt } = require('./jwt');
const { sha256Base64 } = require('./digest');
const { encryptRequest, decryptResponse } = require('./mle');

const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);

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
 *   const res = await client.post('/pts/v2/payments', payload, { mle: 'both' });
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
      defaultMle = 'none',
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
    this.defaultMle = defaultMle;
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

  /** Normalize an mle option ('none'|'request'|'response'|'both' or {request,response}) to booleans. */
  _normalizeMle(spec) {
    if (!spec || spec === 'none') return { request: false, response: false };
    if (spec === 'request') return { request: true, response: false };
    if (spec === 'response') return { request: false, response: true };
    if (spec === 'both') return { request: true, response: true };
    if (typeof spec === 'object') return { request: !!spec.request, response: !!spec.response };
    throw new Error(`Invalid mle option: ${JSON.stringify(spec)} (use 'none'|'request'|'response'|'both' or {request,response})`);
  }

  _resolveMle(mle) {
    return this._normalizeMle(mle === undefined ? this.defaultMle : mle);
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
   * Core request flow. Returns { status, ok, headers, data, jwt, request }.
   * `jwt` and `request` are returned so you can inspect/troubleshoot a failed call.
   */
  async request(method, path, body, opts = {}) {
    method = method.toUpperCase();
    const mle = this._resolveMle(opts.mle);
    const hasBody = body !== undefined && body !== null;

    // 1. Serialize the body and (if request MLE) encrypt it first — the digest must cover
    //    the exact bytes we send, so encryption happens before digesting.
    let bodyString;
    if (hasBody) {
      let outbound = body;
      if (mle.request) {
        outbound = await encryptRequest(JSON.stringify(body), {
          cert: this.requestKeys.mleCert,
          mleSerial: this.requestKeys.mleSerial,
        });
      }
      bodyString = JSON.stringify(outbound);
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

    // 3. Sign it.
    const jwt = buildJwt(claims, { kid: this.requestKeys.signingSerial }, this.requestKeys.privateKeyPem);

    // 4. Send it. For JWT auth the ONLY auth header is Authorization: Bearer <jwt>.
    const url = `https://${this.runEnvironment}${path}`;
    const headers = {
      Authorization: `Bearer ${jwt}`,
      'v-c-client-id': this.clientId,
      'User-Agent': this.clientId,
      Accept: 'application/json',
    };
    if (bodyString != null) headers['Content-Type'] = 'application/json';

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
    if (mle.response && data && typeof data === 'object' && data.encryptedResponse) {
      data = await decryptResponse(data.encryptedResponse, this._ensureResponseKeys().responsePrivateKeyPem);
    }

    return {
      status: res.status,
      ok: res.ok,
      headers: Object.fromEntries(res.headers),
      data,
      jwt,
      request: { url, method, body: bodyString },
    };
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
