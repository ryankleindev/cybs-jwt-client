# cybs-jwt-client

A small, **transparent** toolkit for Cybersource REST API authentication. It exists to
make the JWT auth process (and the newer **Message-Level Encryption** requirements)
easy to *understand and troubleshoot* — not to be another heavyweight SDK.

You point it at your keys, and `get/post/put/patch/delete` just work. The JWT signing is
hand-rolled with Node's built-in `crypto` so you can read exactly what gets signed.

> ⚠️ Built for learning, prototyping, and troubleshooting. Review it before relying on it
> in production.

## Install

```bash
npm install
cp .env.example .env   # then fill it in
```

Requires Node 18+ (uses the global `fetch`).

## Quick start

```js
const { CybsJwtClient, decodeJwt } = require('./src');

const client = new CybsJwtClient({
  runEnvironment: 'apitest.cybersource.com', // production: api.cybersource.com
  merchantId: 'my_mid',
  useMetaKey: true,                          // meta key = portfolio-based auth
  portfolioId: 'my_portfolio_id',
  requestP12:  { path: 'keys/request.p12',  password: '••••' },
  responseP12: { path: 'keys/response.p12', password: '••••' }, // only for response MLE
});

const res = await client.post('/pts/v2/payments', payload, { mle: 'none' });
console.log(res.status, res.data);
console.log(decodeJwt(res.jwt).payload); // inspect the claims you signed
```

Run the included example:

```bash
node examples/payment.js
```

## How the auth works

On a JWT request the **only** auth header is `Authorization: Bearer <jwt>`. Everything else
lives *inside* the signed token:

**Header** — `{ "typ": "JWT", "alg": "RS256", "kid": "<cert serial number>" }`
The `kid` is the `serialNumber` attribute of your signing certificate's subject.

**Claims**

| Claim | Value |
|---|---|
| `iat` / `exp` | issued-at / expiry (epoch seconds; `exp = iat + 120`) |
| `request-host` | the run environment, e.g. `apitest.cybersource.com` |
| `request-resource-path` | the path, e.g. `/pts/v2/payments` |
| `request-method` | lowercase verb |
| `iss` | **portfolio id (meta key)** or merchant id (standard key) |
| `jti` | random UUID |
| `v-c-jwt-version` | `"2"` |
| `v-c-merchant-id` | your MID |
| `digest` / `digest-algorithm` | **POST/PUT/PATCH only** — base64(SHA-256(body)) / `"SHA-256"` |
| `v-c-response-mle-kid` | **response MLE only** — serial of your response cert |

The token is signed **RS256** with your private key. No separate `Digest`/`Date`/`Host`/
`Signature` headers — those belong to the *HTTP Signature* scheme, not JWT.

## Standard key vs meta key

- **Standard key**: you authenticate as a single merchant. `iss` and the signing cert's
  CN are your **MID**.
- **Meta key**: you authenticate with a **portfolio id** that can act across merchants.
  Set `useMetaKey: true` and provide `portfolioId`. Then `iss` and the signing cert's CN
  are the **portfolio id**.

The client picks the right identity automatically based on `useMetaKey`.

## Message-Level Encryption (MLE)

MLE is configured **per call** because endpoints differ — some support request MLE only,
some request + response, some none.

```js
await client.post(path, body, { mle: 'none' });     // no encryption (default)
await client.post(path, body, { mle: 'request' });  // encrypt request only
await client.post(path, body, { mle: 'response' }); // decrypt response only
await client.post(path, body, { mle: 'both' });     // both
// or: { mle: { request: true, response: false } }
```

You can set a client-wide default with `defaultMle`.

### Two p12 files, three keys

| Key | Lives in | Used for |
|---|---|---|
| Signing private key (CN = MID/portfolio) | **request** p12 | signing the JWT |
| Cybersource public cert (CN = `CyberSource_SJC_US`) | **request** p12 | **encrypting** the request to Cybersource |
| Your response private key (CN = MID/portfolio) | **response** p12 | **decrypting** the response |

- **Request MLE**: the JSON body is JWE-encrypted (RSA-OAEP-256 / A256GCM) to Cybersource's
  public cert and sent as `{ "encryptedRequest": "<jwe>" }`. The JWT `digest` is computed
  over this encrypted envelope (the bytes actually sent).
- **Response MLE**: the JWT carries `v-c-response-mle-kid`; Cybersource returns
  `{ "encryptedResponse": "<jwe>" }`, which the client decrypts with your response key.

The JWE library (`jose`) is the one piece not hand-rolled — same choice the official SDK
makes; the teaching focus is the JWT flow.

## Troubleshooting

- **Decode what you signed.** `decodeJwt(res.jwt).payload` shows the exact claims. Every
  call also returns `res.request` (url, method, body) and `res.jwt`.
- **401 / authentication failed** — check `iss` matches the right id (portfolio for meta
  key), `kid` matches your cert serial, `request-host`/`request-resource-path` match the
  URL you hit, and your clock isn't off by >2 minutes (token `exp`).
- **Digest mismatch** — the `digest` claim must hash the *exact* bytes sent. With request
  MLE on, it hashes the encrypted envelope, not the plaintext.
- **"alias not found"** — the error lists the CNs found in the p12. For meta key the
  signing cert CN should be your portfolio id; override with `requestP12.keyAlias` if needed.

## Config reference

```js
new CybsJwtClient({
  runEnvironment,            // required, e.g. 'apitest.cybersource.com'
  merchantId,               // required
  useMetaKey,               // default false
  portfolioId,              // required when useMetaKey is true
  requestP12: {
    path, password,
    keyAlias,               // optional; defaults to portfolioId or merchantId
    mleCertAlias,           // optional; defaults to 'CyberSource_SJC_US'
  },
  responseP12: {            // optional; only needed for response MLE
    path, password,
    kid,                    // optional explicit kid override
  },
  defaultMle,               // optional; 'none' | 'request' | 'response' | 'both'
  clientId,                 // optional; sent as v-c-client-id / User-Agent
});
```
