'use strict';

/**
 * Runnable end-to-end example.
 *
 *   1. cp .env.example .env   (and fill it in)
 *   2. npm install
 *   3. node examples/payment.js
 *
 * It builds a meta-key (or standard-key) client, POSTs a test payment to
 * /pts/v2/payments, then prints the signed JWT's decoded claims and the API response.
 * Toggle MLE with CYBS_MLE_REQUEST / CYBS_MLE_RESPONSE (true|false) in .env.
 */

const fs = require('fs');
const path = require('path');
const { CybsJwtClient, decodeJwt } = require('../src');

// --- tiny .env loader (no dependency) -------------------------------------------------
function loadEnv() {
  const envPath = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (!(key in process.env)) process.env[key] = value;
  }
}
loadEnv();

const env = process.env;
const bool = (v) => String(v).toLowerCase() === 'true';

// --- the payload (replace with the one you want to send) ------------------------------
const payload = {
  clientReferenceInformation: { code: 'cybs-jwt-client-test' },
  processingInformation: { capture: false },
  paymentInformation: {
    card: {
      number: '4111111111111111',
      expirationMonth: '12',
      expirationYear: '2031',
      securityCode: '123',
    },
  },
  orderInformation: {
    amountDetails: { totalAmount: '102.21', currency: 'USD' },
    billTo: {
      firstName: 'John',
      lastName: 'Doe',
      address1: '1 Market St',
      locality: 'San Francisco',
      administrativeArea: 'CA',
      postalCode: '94105',
      country: 'US',
      email: 'test@cybs.com',
      phoneNumber: '4158880000',
    },
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
  console.log(`\n→ POST /pts/v2/payments  (mle request=${mle.request}, response=${mle.response})\n`);

  const res = await client.post('/pts/v2/payments', payload, { mle });

  // Show exactly what we signed — the core troubleshooting view.
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
