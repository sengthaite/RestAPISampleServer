
const crypto = require('crypto');

// Generate RSA key pair with DER encoding
// Generate RSA key pair with DER encoding, then convert to PEM for Node.js crypto compatibility
const { publicKey: pubDer, privateKey: privDer } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'der'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'der',
        cipher: 'aes-256-cbc',
        passphrase: 'your-passphrase'
    }
});

// Convert DER buffers to PEM strings for use with crypto.publicEncrypt/privateDecrypt
function derToPem(derBuffer, label) {
    const base64 = derBuffer.toString('base64');
    const lines = base64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

const publicKey = derToPem(pubDer, 'PUBLIC KEY');
const privateKey = derToPem(privDer, 'ENCRYPTED PRIVATE KEY');

// Encrypt with DER public key
function encryptRSA(plaintext, publicKey) {
    const encrypted = crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }, Buffer.from(plaintext));
    return encrypted.toString('base64');
}

// Decrypt with DER private key
function decryptRSA(ciphertext, privateKey) {
    const decrypted = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        passphrase: 'your-passphrase'
    }, Buffer.from(ciphertext, 'base64'));
    return decrypted.toString('utf8');
}

// Usage
const message = "Hello, World with DER!";
const encrypted = encryptRSA(message, publicKey);
const decrypted = decryptRSA(encrypted, privateKey);

console.log("Encrypted (base64):", encrypted);
console.log("Decrypted:", decrypted);