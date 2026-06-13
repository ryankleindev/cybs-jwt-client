# CLAUDE.md — cybs-jwt-client

A small, **transparent** toolkit for Cybersource REST API JWT authentication with per-call
Message-Level Encryption (MLE). Built to **teach and troubleshoot** the auth process — not
as a production SDK. Standard key and meta key are both first-class.

## Why this exists

Cybersource's official `cybersource-rest-client-node` SDK works but buries the auth logic
across many files. As Cybersource rolls out **MLE requirements** platform-wide, people
struggle to understand and debug the JWT + encryption flow. This package strips it to the
essentials with the JWT signing **hand-rolled and commented** so it can be read and fixed.

## Architecture

- `src/client.js` — `CybsJwtClient` class. Configured once with auth params; exposes
  `get/post/put/patch/delete` over a private `request()`. Native global `fetch` transport.
- `src/jwt.js` — **hand-rolled** RS256 sign + `decodeJwt`, using Node's built-in `crypto`.
  Intentionally no JWT library: every step is visible. This is the teaching core.
- `src/keystore.js` — `node-forge` p12 loaders (`loadRequestP12`, `loadResponseP12`),
  alias/CN matching, cert serial extraction. Cached by file path.
- `src/mle.js` — JWE encrypt/decrypt via `jose` (the ONE place a crypto lib is used; JWE
  is too intricate to hand-roll and the SDK uses jose too).
- `src/digest.js` — SHA-256 base64 of the request body.
- `examples/` — runnable, env-driven: `instrument-identifier.js`, `tokenize.js`, `payment.js`.

## Key concepts (don't relearn these)

- **Wire format**: the only auth header is `Authorization: Bearer <jwt>`. Everything else
  (digest, host, path, method, issuer) lives *inside* the signed token. No separate
  Digest/Date/Host/Signature headers — those belong to HTTP-Signature auth, not JWT.
- **JWT `kid`** = the `serialNumber` attribute of the signing cert's subject.
- **Standard vs meta key**: `useMetaKey` flag. Meta key → `iss` and signing-cert alias are
  the **portfolio id**; standard → the **MID**. `v-c-merchant-id` is always the MID.
- **Two p12 files, three keys** (see memory `mle-uses-three-distinct-keys`):
  - request p12 → (1) signing private key + (2) Cybersource request-MLE *public* cert
    (CN `CyberSource_SJC_US`).
  - response p12 → (3) your response-MLE *private* key (separate cert, separate serial).
- **Encrypt-then-digest ordering**: with request MLE on, the `digest` claim hashes the
  encrypted `{encryptedRequest}` envelope — the exact bytes sent, not the plaintext.
- **MLE API**: per-call, two explicit booleans `{ mle: { request, response } }`, both
  default false. `defaultMle` (same shape) sets a client-wide baseline; per-call overrides
  per key. No string shorthand — explicitness over conciseness (user preference).

## Conventions

- CommonJS, Node 18+ (relies on global `fetch`). Deps: `jose`, `node-forge` only.
- **Never commit secrets.** `.env` and `keys/*.p12` are gitignored; verify nothing
  sensitive is staged before every commit (`git status --short | grep -iE 'p12|\.env$'`).
- Prefer explicitness and clarity over cleverness throughout (user preference).
- Sandbox test config lives in `.env` (gitignored): meta key portfolio `rk_cp_sandbox`,
  MID `rk_cp_sandbox1003`, host `apitest.cybersource.com`.

## Verifying changes

Run an example end-to-end against the sandbox (keys + `.env` already in place):

```bash
node examples/instrument-identifier.js     # baseline JWT auth (no MLE)
node examples/tokenize.js                   # request + response MLE round-trip (live decrypt)
```

Expect HTTP 200. Each result includes `res.jwt` and `res.request`; use
`decodeJwt(res.jwt).payload` to inspect the signed claims when troubleshooting.

## Status

Local git repo, not yet published to npm. JWT signing, standard/meta key, all HTTP methods,
and per-call request/response MLE are implemented and verified live against the sandbox.
