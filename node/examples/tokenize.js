'use strict';

/**
 * TMS tokenize (/tms/v2/tokenize) — creates a customer/token bundle from a card.
 *
 *   node examples/tokenize.js
 *
 * This endpoint supports BOTH request and response MLE, so it's the one that actually
 * exercises live response decryption. It runs with { request: true, response: true }.
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

const REQUEST_PATH = '/tms/v2/tokenize';
const payload = {
  processingInformation: {
    actionList: ['TOKEN_CREATE'],
    actionTokenTypes: ['customer', 'shippingAddress', 'paymentInstrument', 'instrumentIdentifier'],
  },
  tokenInformation: {
    customer: {
      buyerInformation: { merchantCustomerID: 'Your customer identifier', email: 'test@cybs.com' },
      clientReferenceInformation: { code: 'TC50171_3' },
      merchantDefinedInformation: [{ name: 'data1', value: 'Your customer data' }],
    },
    shippingAddress: {
      default: 'true',
      shipTo: {
        firstName: 'John',
        lastName: 'Doe',
        company: 'Cybersource Developer Center',
        address1: '1 Market St',
        locality: 'San Francisco',
        administrativeArea: 'CA',
        postalCode: '94105',
        country: 'US',
        email: 'test@cybs.com',
        phoneNumber: '4158880000',
      },
    },
    paymentInstrument: {
      default: 'true',
      card: { expirationMonth: '12', expirationYear: '2031', type: '001' },
      billTo: {
        firstName: 'John',
        lastName: 'Doe',
        company: 'Cybersource Developer Center',
        address1: '1 Market St',
        locality: 'San Francisco',
        administrativeArea: 'CA',
        postalCode: '94105',
        country: 'US',
        email: 'test@cybs.com',
        phoneNumber: '4158880000',
      },
    },
    instrumentIdentifier: {
      type: 'enrollable card',
      card: { number: '4622943123116478', expirationMonth: '12', expirationYear: '2026' },
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

  // This endpoint supports both directions, so demonstrate the full encrypt + decrypt round-trip.
  const mle = { request: true, response: true };
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
