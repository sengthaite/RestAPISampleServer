const crypto = require('crypto');

// Generate RSA-PSS key pair with specific parameters
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa-pss', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: 'top-secret'
    },
    // PSS-specific options
    hashAlgorithm: 'sha256',
    mgf1HashAlgorithm: 'sha256',  // Mask Generation Function
    saltLength: 32
});

// Data to be signed
const message = 'Hello, RSA-PSS!';

// Create signature
function signMessage(message, privateKey, passphrase) {
    const signer = crypto.createSign('sha256');
    signer.update(message);
    const signature = signer.sign({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        passphrase,
        saltLength: 32
    });
    return signature;
}

// Verify signature
function verifySignature(message, signature, publicKey) {
    const verifier = crypto.createVerify('sha256');
    verifier.update(message);
    return verifier.verify({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_AUTO
    }, signature);
}

// Usage
try {
    // Sign the message
    const signature = signMessage(message, privateKey, 'top-secret');
    console.log('Signature:', signature.toString('base64'));

    // Verify the signature
    const isValid = verifySignature(message, signature, publicKey);
    console.log('Signature is valid:', isValid);

    // Try verifying with modified message
    const isValidModified = verifySignature(message + 'tampered', signature, publicKey);
    console.log('Modified message signature is valid:', isValidModified); // Should be false
} catch (error) {
    console.error('Error:', error);
}