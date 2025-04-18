
/**
 * Demonstrates RSA-PSS signing and verification using different salt length options in Node.js crypto module.
 *
 * Salt Length Options:
 * - `RSA_PSS_SALTLEN_DIGEST`: The salt length is set to the length of the hash function's digest (e.g., 32 bytes for SHA-256).
 * - `RSA_PSS_SALTLEN_MAX_SIGN`: The salt length is set to the maximum allowed for the key size and hash function, maximizing security.
 * - `RSA_PSS_SALTLEN_AUTO`: During verification, the salt length is automatically determined from the signature, allowing flexibility in accepting signatures with varying salt lengths.
 *
 * This example shows how signatures created with different salt lengths can be verified using the AUTO option.
 */

const crypto = require('crypto');

// Generate a key pair for demonstration
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

// Data to sign
const data = Buffer.from('Hello, world!');

// --- Signing with RSA_PSS_SALTLEN_DIGEST ---
const signatureDigest = crypto.sign(null, data, {
  key: privateKey,
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
});

// --- Signing with RSA_PSS_SALTLEN_MAX_SIGN ---
const signatureMax = crypto.sign(null, data, {
  key: privateKey,
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
});

// --- Verifying with RSA_PSS_SALTLEN_AUTO ---
const isValidDigest = crypto.verify(null, data, {
  key: publicKey,
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: crypto.constants.RSA_PSS_SALTLEN_AUTO,
}, signatureDigest);

const isValidMax = crypto.verify(null, data, {
  key: publicKey,
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: crypto.constants.RSA_PSS_SALTLEN_AUTO,
}, signatureMax);

console.log('Signature with DIGEST salt valid:', isValidDigest);
console.log('Signature with MAX_SIGN salt valid:', isValidMax);