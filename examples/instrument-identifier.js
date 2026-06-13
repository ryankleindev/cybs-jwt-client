'use strict';

/**
 * Creates a TMS instrument identifier (tokenizes a PAN).
 *
 *   node examples/instrument-identifier.js
 *
 * Toggle MLE with CYBS_MLE_REQUEST / CYBS_MLE_RESPONSE (true|false) in .env. Because the
 * payload carries a raw card number, this endpoint is a good one for exercising MLE.
 */

const fs = require('fs');
const path = require('path');
const { CybsJwtClient, decodeJwt } = require('../src');

function loadEnv() {
  const envPath = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    if (!(key in process.env)) process.env[key] = trimmed.slice(eq + 1).trim();
  }
}
loadEnv();

const env = process.env;
const bool = (v) => String(v).toLowerCase() === 'true';

const REQUEST_PATH = '/tms/v1/instrumentidentifiers';
const payload = {
  card: {
    number: '4111111111111111',
  },
};

async function main() {
  const client = new CybsJwtClient({
    runEnvironment: env.CYBS_RUN_ENVIRONMENT || 'apitest.cybersource.com',
    merchantId: env.CYBS_MERCHANT_ID,
    useMetaKey: bool(env.CYBS_USE_META_KEY),
    portfolioId: env.CYBS_PORTFOLIO_ID,
    requestP12: {
      path: env.CYBS_REQUEST_P12_PATH || 'keys/rk_cp_sandbox_request.p12',
      password: env.CYBS_REQUEST_P12_PASSWORD,
    },
    responseP12: {
      path: env.CYBS_RESPONSE_P12_PATH || 'keys/rk_cp_sandbox_response.p12',
      password: env.CYBS_RESPONSE_P12_PASSWORD,
    },
  });

  const mle = { request: bool(env.CYBS_MLE_REQUEST), response: bool(env.CYBS_MLE_RESPONSE) };
  console.log(`\n→ POST ${REQUEST_PATH}  (mle request=${mle.request}, response=${mle.response})\n`);

  const res = await client.post(REQUEST_PATH, payload, { mle });

  const decoded = decodeJwt(res.jwt);
  console.log('JWT header :', JSON.stringify(decoded.header));
  console.log('JWT claims :', JSON.stringify(decoded.payload, null, 2));

  console.log(`\nHTTP ${res.status} ${res.ok ? 'OK' : 'ERROR'}`);
  console.log('Response   :', JSON.stringify(res.data, null, 2));

  process.exit(res.ok ? 0 : 1);
}

main().catch((err) => {
  console.error('\nRequest failed:', err.message);
  process.exit(1);
});
