# cybs-jwt-client

A small, **transparent** toolkit for Cybersource REST API authentication. It exists to
make the JWT auth process (and the newer **Message-Level Encryption** requirements)
easy to *understand and troubleshoot* — not to be another heavyweight SDK.

You point it at your keys, and `get/post/put/patch/delete` just work. It's built on the
standard libraries (`jose` for the JWT and JWE, `node-forge` for p12 files), with every
Cybersource-specific value set explicitly so you can read exactly what gets sent. Both of
Cybersource's JWT signing methods are supported: a **certificate** (p12, RS256) or a
**shared secret** (HMAC, HS256/384/512).

> ⚠️ Built for learning, prototyping, and troubleshooting. Review it before relying on it
> in production.

## Install

```bash
npm install @ryankleindev/cybs-jwt-client
```

Requires Node 20.19+ (uses the global `fetch`, and loads the ESM-only `jose` 6).

> Want to run the bundled `examples/`? Those live in the repo, not the published package —
> clone [the repo](https://github.com/ryankleindev/cybs-jwt-client), `npm install` inside
> `node/`, then `cp .env.example .env` and drop your `.p12` files in `keys/`.

## Quick start

```js
const { CybsJwtClient } = require('@ryankleindev/cybs-jwt-client');

const client = new CybsJwtClient({
  runEnvironment: 'apitest.cybersource.com', // production: api.cybersource.com
  merchantId: 'my_mid',
  useMetaKey: true,                          // meta key = portfolio-based auth
  portfolioId: 'my_portfolio_id',
  requestP12:  { path: 'keys/request.p12',  password: '••••' },
  responseP12: { path: 'keys/response.p12', password: '••••' }, // only for response MLE
});

const res = await client.post('/pts/v2/payments', payload, {
  mle: { request: false, response: false },
});
console.log(res.status, res.data);   // the answer (decrypted, if response MLE)
console.log(res.trace.jwt.claims);   // exactly what you signed — already decoded for you
```

Signing with a shared secret instead? Swap `requestP12` for `sharedSecret`:

```js
const client = new CybsJwtClient({
  runEnvironment: 'apitest.cybersource.com',
  merchantId: 'my_mid',
  sharedSecret: { keyId: 'my_key_id', secret: '<base64 secret from Business Center>' },
  responseP12: { path: 'keys/response.p12', password: '••••' }, // for MLE (either direction)
});
```

Every call returns `{ ok, status, data, trace }`. `data` is the result you usually want;
`trace` is the glassbox — see [The trace](#the-trace-glassbox) below.

Run the included example:

```bash
node examples/payment.js
```

## How the auth works

On a JWT request the **only** auth header is `Authorization: Bearer <jwt>`. Everything else
lives *inside* the signed token:

**Header** — `{ "typ": "JWT", "alg": "RS256", "kid": "<cert serial number>" }`
The `kid` is the `serialNumber` attribute of your signing certificate's subject. With a
shared secret it's `{ "typ": "JWT", "alg": "HS256", "kid": "<shared secret key id>" }`.

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

No separate `Digest`/`Date`/`Host`/`Signature` headers — those belong to the *HTTP
Signature* scheme, not JWT.

### Two ways to sign

The claims are identical either way; only the signature step differs.

| | Certificate | Shared secret |
|---|---|---|
| Config | `requestP12: { path, password }` | `sharedSecret: { keyId, secret, alg? }` |
| `alg` | `RS256` | `HS256` (default), `HS384`, or `HS512` |
| `kid` | your signing cert's serial number | the shared secret's key id |
| Signature | RSA-SHA256 with your private key | HMAC with the secret's **base64-decoded** bytes |
| Request MLE cert | request p12 (falls back to response p12) | response p12 |

Create a shared secret in Business Center under **Payment Configuration > Key Management >
Generate key > REST – Shared Secret**. The secret is shown base64-encoded; the client decodes
it before computing the HMAC. Using the base64 *text* as the HMAC key is a common cause of a
401 with a token that otherwise looks perfect.

## Standard key vs meta key

- **Standard key**: you authenticate as a single merchant. `iss` and the signing cert's
  CN are your **MID**.
- **Meta key**: you authenticate with a **portfolio id** that can act across merchants.
  Set `useMetaKey: true` and provide `portfolioId`. Then `iss` and the signing cert's CN
  are the **portfolio id**.

The client picks the right identity automatically based on `useMetaKey`.

## Message-Level Encryption (MLE)

MLE is configured **per call** because endpoints differ — some support request MLE only,
some request + response, some none. It's always two explicit, independent booleans, and
both default to `false`:

```js
await client.post(path, body);                                       // no MLE (both default false)
await client.post(path, body, { mle: { request: true,  response: false } }); // encrypt request only
await client.post(path, body, { mle: { request: false, response: true  } }); // decrypt response only
await client.post(path, body, { mle: { request: true,  response: true  } }); // both
```

A per-call spec can set just one side (`{ mle: { request: true } }`) — the other falls
back to the configured default. You can set that client-wide default with `defaultMle`,
which takes the same `{ request, response }` shape (useful as Cybersource makes MLE
mandatory across more of the platform):

```js
new CybsJwtClient({ /* ... */, defaultMle: { request: true, response: true } });
```

### Two p12 files, three keys

| Key | Lives in | Used for |
|---|---|---|
| Signing private key (CN = MID/portfolio) | **request** p12 (or a shared secret instead) | signing the JWT |
| Cybersource public cert (CN = `CyberSource_SJC_US`) | **both** p12s | **encrypting** the request to Cybersource |
| Your response private key (CN = MID/portfolio) | **response** p12 | **decrypting** the response |

The `CyberSource_SJC_US` cert is Cybersource's single public MLE cert, and it's **bundled in
every p12 Cybersource issues** — both the request and response downloads carry the same cert.
In fact, Cybersource's getting-started docs tell you to extract it from the *Response* MLE Key
download. The client reads the request p12 first and **falls back to the response p12** if the
cert isn't there, so request MLE works regardless of which download you got it from. Override
the alias with `requestP12.mleCertAlias` / `responseP12.mleCertAlias` if needed.

With a **shared secret** there's no request p12, so the response p12 is the only key file:
it supplies Cybersource's public cert for request MLE and your private key for response MLE.

- **Request MLE**: the JSON body is JWE-encrypted (RSA-OAEP-256 / A256GCM) to Cybersource's
  public cert and sent as `{ "encryptedRequest": "<jwe>" }`. The JWT `digest` is computed
  over this encrypted envelope (the bytes actually sent).
- **Response MLE**: the JWT carries `v-c-response-mle-kid`; Cybersource returns
  `{ "encryptedResponse": "<jwe>" }`, which the client decrypts with your response key.

Both the JWT and the JWE use `jose`; the values Cybersource cares about are set explicitly.

## The trace (glassbox)

Every call returns a `trace` that captures *everything* that happened under the hood, so you
(or a troubleshooting tool) can interrogate the exact values your code produced. It's always
built and **lossless** — it includes plaintext PANs and the bearer JWT verbatim. This is a
glassbox dev/troubleshooting tool, **not** a production client; don't log or expose a trace
where that data would be a problem.

```js
res.trace = {
  request: {
    url, method,
    headers,            // the headers actually sent (incl. `Authorization: Bearer <jwt>`)
    mle,                // resolved { request, response } booleans for this call
    body,               // your plaintext body object (null for GET/DELETE)
    bodySerialized,     // plaintext body as the JSON string
    bodyEncrypted,      // { encryptedRequest } envelope — only when request MLE is on
    bodyWire,           // the EXACT bytes sent — this is what the JWT `digest` hashes
  },
  jwt: {
    compact,            // the signed token string (header.payload.signature)
    header,             // decoded { typ, alg, kid } — kid is your cert serial or shared secret key id
    claims,             // decoded claim set (iat, exp, request-*, digest, ...)
    signing,            // { method: 'certificate' | 'sharedSecret', alg } — never the secret
  },
  encryption: {
    request,            // the JWE protected header we set (alg/enc/kid) — null when off
    response,           // the JWE protected header the server set — null when off
  },
  response: {
    status, headers,
    encrypted,          // raw { encryptedResponse } — only when response MLE came back
    data,               // final decrypted/parsed body (same as top-level `res.data`)
  },
};
```

If a crypto step throws (e.g. the response won't decrypt), the partial trace built so far is
attached to the error as `err.trace` — exactly when you most want to see the JWT and the
encrypted envelope:

```js
try {
  await client.post(path, body, { mle: { response: true } });
} catch (err) {
  console.log(err.trace.jwt.claims);          // what you signed
  console.log(err.trace.response.encrypted);  // the envelope that failed to decrypt
}
```

`decodeJwt` is still exported if you need to decode a token you obtained elsewhere.

## Troubleshooting

- **Inspect what you signed.** `res.trace.jwt.claims` (and `.header`) are already decoded —
  no need to crack the token open yourself. The whole request/response lifecycle is in
  `res.trace`.
- **401 / authentication failed** — check `iss` matches the right id (portfolio for meta
  key), `kid` matches your cert serial (or shared secret key id), `request-host`/
  `request-resource-path` match the URL you hit, and your clock isn't off by >2 minutes
  (token `exp`). With a shared secret, also confirm the secret was copied exactly.
- **Intermittent 401s** — tokens live only ~2 minutes (`exp = iat + 120`), so a caller clock
  running slightly *ahead* of Cybersource's can mint a token the server sees as not-yet-valid.
  The client already backdates `iat` by `clockSkewSeconds` (default 5) to absorb this; bump it
  if a host's clock drifts further. Check `res.trace.jwt.claims.iat` to see the value sent.
- **Digest mismatch** — the `digest` claim must hash the *exact* bytes sent
  (`res.trace.request.bodyWire`). With request MLE on, that's the encrypted envelope, not
  the plaintext.
- **"alias not found"** — the error lists the CNs found in the p12. For meta key the
  signing cert CN should be your portfolio id; override with `requestP12.keyAlias` if needed.

## Config reference

```js
new CybsJwtClient({
  runEnvironment,            // required, e.g. 'apitest.cybersource.com'
  merchantId,               // required
  useMetaKey,               // default false
  portfolioId,              // required when useMetaKey is true
  requestP12: {             // certificate signing; provide this OR sharedSecret
    path, password,
    keyAlias,               // optional; defaults to portfolioId or merchantId
    mleCertAlias,           // optional; defaults to 'CyberSource_SJC_US'
  },
  sharedSecret: {           // shared-secret signing; provide this OR requestP12
    keyId,                  // the key id from Business Center
    secret,                 // the base64 secret from Business Center
    alg,                    // optional; 'HS256' (default), 'HS384', or 'HS512'
  },
  responseP12: {            // response MLE; also request MLE when using sharedSecret
    path, password,
    kid,                    // optional explicit kid override
  },
  defaultMle,               // optional; { request: boolean, response: boolean }, both default false
  clientId,                 // optional; sent as v-c-client-id / User-Agent
  clockSkewSeconds,         // optional; backdate iat to absorb clock drift (default 5)
});
```
