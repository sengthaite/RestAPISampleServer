/**
 * Identifies the format of an RSA public key.
 * Supports PEM (PKCS#1, PKCS#8) and DER (binary) formats.
 * @param {string|Buffer} key - The public key as a string or Buffer.
 * @returns {'pem-pkcs1'|'pem-pkcs8'|'der'|'unknown'} The detected format.
 */
function identifyRsaPublicKeyFormat(key) {
    if (Buffer.isBuffer(key)) {
        // DER format is binary, usually starts with 0x30 (ASN.1 SEQUENCE)
        if (key[0] === 0x30) return 'der';
        return 'unknown';
    }
    if (typeof key !== 'string') return 'unknown';

    if (key.includes('-----BEGIN RSA PUBLIC KEY-----')) return 'pem-pkcs1';
    if (key.includes('-----BEGIN PUBLIC KEY-----')) return 'pem-pkcs8';
    if (/^[A-Za-z0-9+/=\r\n]+$/.test(key.trim())) return 'der'; // base64 DER
    return 'unknown';
}

// Example usage:
const pkcs1Pem = `
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEArv...
-----END RSA PUBLIC KEY-----
`;

const pkcs8Pem = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
-----END PUBLIC KEY-----
`;

const derBuffer = Buffer.from([0x30, 0x82, 0x01, 0x0a, /* ... */]);

console.log(identifyRsaPublicKeyFormat(pkcs1Pem)); // 'pem-pkcs1'
console.log(identifyRsaPublicKeyFormat(pkcs8Pem)); // 'pem-pkcs8'
console.log(identifyRsaPublicKeyFormat(derBuffer)); // 'der'