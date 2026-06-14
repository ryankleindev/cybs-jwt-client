'use strict';

const fs = require('fs');
const forge = require('node-forge');

/**
 * Loads keys/certs out of Cybersource `.p12` files.
 *
 * Two physical p12 files are involved (see README), three logical keys:
 *
 *   request p12  ->  (1) your signing private key   (CN = MID, or portfolio id for meta key)
 *                    (2) Cybersource's request-MLE  (CN = CyberSource_SJC_US) -- public cert
 *   response p12 ->  (3) your response-MLE private key (CN = MID/portfolio)
 *
 * Each parse is cached in memory by file path so we don't re-read/re-decrypt on every call.
 */

const _cache = new Map();

/**
 * Read and decrypt a p12 into a node-forge pkcs12 object (cached by path).
 * @param {string} path
 * @param {string} password
 * @returns {object} forge pkcs12
 */
function parseP12(path, password) {
  if (_cache.has(path)) return _cache.get(path);

  // node-forge wants the DER bytes as a binary string.
  const der = fs.readFileSync(path, 'binary');
  const asn1 = forge.asn1.fromDer(der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password);

  _cache.set(path, p12);
  return p12;
}

/** Pull the common name (CN) out of a forge certificate's subject. */
function certCommonName(cert) {
  for (const attr of cert.subject.attributes) {
    if (attr.name === 'commonName' || attr.shortName === 'CN') return attr.value;
  }
  return null;
}

/**
 * The JWT `kid` (and MLE `kid`) is the certificate's *serial number* — specifically the
 * `serialNumber` attribute of the cert subject, NOT the X.509 serialNumber field.
 */
function certSerialNumber(cert) {
  const attr = cert.subject.attributes.find((a) => a.name === 'serialNumber');
  if (!attr) {
    throw new Error('serialNumber attribute not found in certificate subject');
  }
  return attr.value;
}

/**
 * Find a cert bag in a p12 by alias. Matches the official SDK behaviour (friendlyName
 * contains `cn=<alias>`) and falls back to a direct subject-CN match for robustness.
 * @returns {object|null} the forge cert bag, or null
 */
function findCertBag(p12, alias) {
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  const lower = String(alias).toLowerCase();

  for (const bag of certBags) {
    const fn = bag.attributes && bag.attributes.friendlyName && bag.attributes.friendlyName[0];
    if (fn && fn.toLowerCase().includes(`cn=${lower}`)) return bag;
  }
  for (const bag of certBags) {
    const cn = bag.cert && certCommonName(bag.cert);
    if (cn && cn.toLowerCase() === lower) return bag;
  }
  return null;
}

/** List the CNs of every cert in a p12 — used to produce helpful "alias not found" errors. */
function listCommonNames(p12) {
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  return certBags.map((bag) => bag.cert && certCommonName(bag.cert)).filter(Boolean);
}

/**
 * Extract the (first) RSA private key from a p12 as PEM. Tries the plain key bag, then
 * the PKCS#8 shrouded key bag (mirrors the SDK).
 */
function getPrivateKeyPem(p12) {
  let bags = p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag];
  if (!bags || bags.length === 0) {
    bags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag];
  }
  if (!bags || bags.length === 0 || !bags[0].key) {
    throw new Error('No private key found in p12');
  }
  return forge.pki.privateKeyToPem(bags[0].key);
}

/**
 * Load the request p12: signing key + serial, and the (optional) request-MLE public cert.
 *
 * @param {string} path
 * @param {string} password
 * @param {object} opts
 * @param {string} opts.keyAlias       - CN of your signing cert (MID or portfolio id)
 * @param {string} [opts.mleCertAlias] - CN of the Cybersource request-MLE cert
 * @returns {{privateKeyPem: string, signingSerial: string, mleCert: object|null, mleSerial: string|null}}
 */
function loadRequestP12(path, password, { keyAlias, mleCertAlias = 'CyberSource_SJC_US' }) {
  const p12 = parseP12(path, password);

  const signingBag = findCertBag(p12, keyAlias);
  if (!signingBag) {
    throw new Error(
      `Signing certificate with alias "${keyAlias}" not found in ${path}. ` +
        `Certificates present: [${listCommonNames(p12).join(', ')}]`
    );
  }
  const signingSerial = certSerialNumber(signingBag.cert);
  const privateKeyPem = getPrivateKeyPem(p12);

  // The request-MLE cert is Cybersource's public cert; only present if MLE is set up.
  let mleCert = null;
  let mleSerial = null;
  const mleBag = findCertBag(p12, mleCertAlias);
  if (mleBag) {
    mleCert = mleBag.cert;
    mleSerial = certSerialNumber(mleBag.cert);
  }

  return { privateKeyPem, signingSerial, mleCert, mleSerial };
}

/**
 * Load the response p12: the private key Cybersource encrypts responses to, and the kid
 * (cert serial whose CN matches your MID/portfolio) that goes in the `v-c-response-mle-kid`
 * claim. An explicit `kid` overrides auto-extraction.
 *
 * @param {string} path
 * @param {string} password
 * @param {object} opts
 * @param {string} opts.kidAlias - CN to match for the kid (MID or portfolio id)
 * @param {string} [opts.kid]    - explicit kid override
 * @returns {{responsePrivateKeyPem: string, responseMleKid: string}}
 */
function loadResponseP12(path, password, { kidAlias, kid }) {
  const p12 = parseP12(path, password);
  const responsePrivateKeyPem = getPrivateKeyPem(p12);

  let responseMleKid = kid || null;
  if (!responseMleKid) {
    const bag = findCertBag(p12, kidAlias);
    if (!bag) {
      throw new Error(
        `Response-MLE certificate with alias "${kidAlias}" not found in ${path}, and no ` +
          `explicit kid was provided. Certificates present: [${listCommonNames(p12).join(', ')}]`
      );
    }
    responseMleKid = certSerialNumber(bag.cert);
  }

  return { responsePrivateKeyPem, responseMleKid };
}

module.exports = {
  loadRequestP12,
  loadResponseP12,
  // exported for tests / inspection
  certSerialNumber,
  certCommonName,
  listCommonNames,
  parseP12,
};
