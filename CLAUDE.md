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

The repo is a multi-language monorepo; the Node package lives under `node/` and publishes as
`@ryankleindev/cybs-jwt-client`. All paths below are relative to `node/`. Run npm/node
commands from inside `node/` (`.env` and `keys/` live there too).

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
- **Glassbox return contract**: every call returns `{ ok, status, data, trace }`. `trace`
  is always built and **lossless** (plaintext PANs, bearer JWT, JWE envelopes, decoded
  JWT/JWE headers — nothing redacted) with sections `request` / `jwt` / `encryption` /
  `response`. On a crypto throw the partial trace is attached as `err.trace`. This is a
  deliberate dev/troubleshooting tool, not a production client; a separate project consumes
  the trace to render it in troubleshooting UIs. No `trace.version` field yet (deferred).

## Conventions

- CommonJS, Node 18+ (relies on global `fetch`). Deps: `jose`, `node-forge` only.
- **Never commit secrets.** `.env` and `keys/*.p12` are gitignored; verify nothing
  sensitive is staged before every commit (`git status --short | grep -iE 'p12|\.env$'`).
- Prefer explicitness and clarity over cleverness throughout (user preference).
- Sandbox test config lives in `.env` (gitignored): meta key portfolio `rk_cp_sandbox`,
  MID `rk_cp_sandbox1003`, host `apitest.cybersource.com`.

## Verifying changes

Run an example end-to-end against the sandbox (keys + `.env` already in place under `node/`):

```bash
cd node
node examples/instrument-identifier.js     # baseline JWT auth (no MLE)
node examples/tokenize.js                   # request + response MLE round-trip (live decrypt)
```

Expect HTTP 200. Every call returns `{ ok, status, data, trace }` (see the glassbox trace
note below); inspect `res.trace.jwt.claims` for the signed claims when troubleshooting.

## Status

Restructured into `node/` and prepared as a publishable scoped npm package
(`@ryankleindev/cybs-jwt-client`, `files` allowlist, MIT LICENSE). Pushed to GitHub at
`github.com/ryankleindev/cybs-jwt-client` (public). JWT signing, standard/meta key, all HTTP
methods, and per-call request/response MLE are implemented and verified live against the
sandbox. First `npm publish` is run manually by the maintainer.
