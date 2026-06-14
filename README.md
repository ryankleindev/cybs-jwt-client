# cybs-jwt-client

A small, **transparent** toolkit for Cybersource REST API JWT authentication (standard key
and meta key) with per-call **Message-Level Encryption**. Built to *teach and troubleshoot*
the auth flow — the JWT signing is hand-rolled and commented so every step is readable — not
to be another heavyweight SDK.

> ⚠️ Built for learning, prototyping, and troubleshooting. Review it before relying on it in
> production.

## Implementations

Each language implementation lives in its own subdirectory. Today there's one:

| Language | Directory | Package |
|---|---|---|
| Node.js | [`node/`](node/) | [`@ryankleindev/cybs-jwt-client`](https://www.npmjs.com/package/@ryankleindev/cybs-jwt-client) on npm |

See [`node/README.md`](node/README.md) for install, usage, the auth walkthrough, and
troubleshooting.

```bash
npm install @ryankleindev/cybs-jwt-client
```

## License

[MIT](node/LICENSE) © Ryan Klein
