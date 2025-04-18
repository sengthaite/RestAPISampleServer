import * as crypto from 'crypto';
import express, { Request, Response } from 'express';
import { Readable } from "stream";
import * as zlib from "zlib";

const app = express();
const cors = require("cors");
const { pipeline } = require('node:stream');
const easyxml = require('easyxml');
const port = process.env.PORT ?? 3000;

app.use(cors());

let serializer = new easyxml({
    singularize: true,
    rootElement: 'response',
    dateFormat: 'ISO',
    manifest: true
});


app.get('/get', (req: Request, res: Response) => {
    res.send('Success');
});

app.get("/get-json", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "application/json");
    res.json({ "express": "get-json success" })
})

app.get("/get-html", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "text/html");
    res.sendFile(__dirname + '/public/html/hello.html');
})

app.get("/get-xml", (req: Request, res: Response) => {
    res.header('Content-Type', 'text/xml');
    let obj = {
        items: [{
            name: 'one',
            _id: 1
        }, {
            name: 'two',
            _id: 2
        }, {
            name: 'three',
            _id: 3
        }],
        blah: 'http://www.google.com',
        when: new Date(),
        boolz: true,
        nullz: null
    };
    let xml = serializer.render(obj);
    res.send(xml);
})

app.get("/get-png", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "image/png");
    res.sendFile(__dirname + '/public/image/penguin.png');
})

app.get("/get-svg", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "image/svg+xml");
    res.sendFile(__dirname + '/public/image/atom.svg');
})

app.get("/get-movie", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "video/mp4");
    res.sendFile(__dirname + "/public/video/test.mp4");
})

app.get("/get-gif", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "image/gif");
    res.sendFile(__dirname + "/public/image/animate.gif");
})

app.get("/get-zip", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "application/zip");
    res.sendFile(__dirname + "/public/file/font.zip");
})

app.get("/get-gzip", (request: Request, response: Response) => {
    const raw = Readable.from([Buffer.from("Hello, world!")]);
    response.setHeader('Vary', 'Accept-Encoding');
    let acceptEncoding = request.headers['accept-encoding'] as string;
    if (!acceptEncoding) {
        acceptEncoding = '';
    }
    const onError = (err: any) => {
        if (err) {
            response.end();
            console.error('An error occurred:', err);
        }
    };
    if (/\bdeflate\b/.test(acceptEncoding)) {
        response.writeHead(200, { 'Content-Encoding': 'deflate' });
        pipeline(raw, zlib.createDeflate(), response, onError);
    } else if (/\bgzip\b/.test(acceptEncoding)) {
        response.writeHead(200, { 'Content-Encoding': 'gzip' });
        pipeline(raw, zlib.createGzip(), response, onError);
    } else if (/\bbr\b/.test(acceptEncoding)) {
        response.writeHead(200, { 'Content-Encoding': 'br' });
        pipeline(raw, zlib.createBrotliCompress(), response, onError);
    } else {
        response.writeHead(200, {});
        pipeline(raw, response, onError);
    }
});

///AuthType
app.get("/auth-type", (request: Request, response: Response) => {
    const authheader = request.headers.authorization;
    console.log(request.headers);

    if (!authheader) {
        let err = new Error('You are not authenticated!');
        response.setHeader('WWW-Authenticate', 'Basic');
        response.statusCode = 401
        response.send(err)
        return
    }

    const auth = Buffer.from(authheader.split(' ')[1],
        'base64').toString().split(':');
    const user = auth[0];
    const pass = auth[1];
    console.log(`user ${user}`);
    console.log(`password ${pass}`);
    response.send("success")
});

/// encryption
// 1. aes encryption

// Add these constants after the existing AES constants
// POST /aes/256/cbc/encrypt
// POST /aes/256/cbc/decrypt
const keySizes = [128, 192, 256];
const keys = new Map();

// Update the modes constant with all supported modes
const modes = [
    'ofb',  // Output Feedback
    'gcm',  // Galois/Counter Mode
    'ecb',  // Electronic Codebook
    'ctr',  // Counter
    'cfb',  // Cipher Feedback
    'ccm',  // Counter with CBC-MAC
    'cbc',  // Cipher Block Chaining
    'ocb',  // Offset Codebook Mode
    'xts', // XOR-based stream
] as const;

type AESMode = typeof modes[number];

// Define which modes require IV/Nonce
const requiresIV: Record<AESMode, boolean> = {
    'cbc': true,
    'ccm': true,
    'cfb': true,
    'ctr': true,
    'ecb': false,
    'gcm': true,
    'ocb': true,
    'ofb': true,
    "xts": true
};

// Define which modes require authentication tag
const requiresAuth: Record<AESMode, boolean> = {
    'cbc': false,
    'ccm': true,
    'cfb': false,
    'ctr': false,
    'ecb': false,
    'gcm': true,
    'ocb': true,
    'ofb': false,
    'xts': false,
};


// Initialize keys and IVs for each combination
modes.forEach(mode => {
    keySizes.forEach(size => {
        const algorithm = `aes-${size}-${mode}`;
        if (mode == 'xts' && size != 192) {
            keys.set(algorithm, crypto.randomBytes((size / 8) * 2));
        } else if (mode != 'xts') {
            keys.set(algorithm, crypto.randomBytes(size / 8));
        }
    });
});

function getIV(mode: AESMode, plainTextBufferLength: number) {
    let iv = null;
    if (requiresIV[mode]) {
        switch (mode) {
            case 'ofb':
                /**
                 * Output Feedback
                 * =================
                 * IV length must be: 16
                 */
                iv = crypto.randomBytes(16);
                break;
            case 'gcm':
                /**
                 * Galois/Counter Mode
                 * ===================
                 * Initialization Vector (IV) range: 1 - 128
                 * Recommended IV: 12
                 */
                iv = crypto.randomBytes(128);
                break;
            case 'ecb':
                /**
                 * Electronic Codebook
                 * ====================
                 * No IV required
                 * No authTag
                 */
                break;
            case 'ctr':
                /**
                 * Counter Mode
                 * ============
                 * Initialization Vector (IV) length: 16
                 * IV must be length (Nonce + counter): 16
                 */
                iv = crypto.randomBytes(16);
                break;
            case 'cfb':
                /**
                 * Cipher Feedback
                 * ===============
                 * Initialization Vector (IV) length: 16
                 * IV must be length: 16
                 */
                iv = crypto.randomBytes(16);
                break;
            case 'ccm':
                /**
                 * Cipher Block Chaining with Message Authentication Code
                 * =======================================================
                 * authTagLength (even number): 4, 6, 8, 10, 12, 14, or 16
                 * Recommended authTagLength: 16
                 * Inititalization Vector (IV) length: 7 - 13
                 * Recommended IV length: 12
                 * IV must be unique for each encryption
                 */
                iv = crypto.randomBytes(13);
                break;
            case 'ocb':
                /**
                 * Offset Codebook
                 * ================
                 * Recommended authTagLength: 16
                 * Valid authTagLength range: 1 - 16
                 * Recommended Initialization Vector (IV) length: 12
                 * Valid IV length range: 1 - 15
                 */
                iv = crypto.randomBytes(15);
                break;
            case 'cbc':
                /**
                 * iv must be 16 bytes for cbc
                 * No authTag
                 */
                iv = crypto.randomBytes(16);
                break;
            case 'xts':
                /**
                 * XOR-based stream
                 * ================
                 * IV length must be: 16
                 * Keysize support: 256 (128 * 2) or 512 (256 * 2)
                 * Designed to encrypt data in sectors/blocks (like disk encryption)
                 */
                if (plainTextBufferLength < 16) {
                    console.log('Plaintext size must not be smaller than the AES block sizes (16 bytes)');
                    return;
                }
                iv = crypto.randomBytes(16);
                break;
        }
    }
    return iv;
}

function getOptions(mode: AESMode, plainTextBufferLength: number) {
    let options = {};
    if (requiresIV[mode]) {
        switch (mode) {
            case 'ccm':
                options = { authTagLength: 16, plaintextLength: plainTextBufferLength };
                break;
            case 'ocb':
                options = { authTagLength: 16 };
                break;
        }
    }
    return options;
}

function encryptAES(plaintext: any, mode: string, algorithm: string, aad: string) {

    if (!plaintext) {
        console.log('Plaintext is required')
        return;
    }

    if (!modes.includes(mode as AESMode)) {
        console.log(`Invalid mode ${mode}`);
        return;
    }

    try {
        const key = keys.get(algorithm);
        let iv = getIV(mode as AESMode, Buffer.from(plaintext).length);
        let options = getOptions(mode as AESMode, Buffer.from(plaintext).length);

        const plainTextBufferLength = Buffer.from(plaintext).length;

        const cipher = iv
            ? crypto.createCipheriv(algorithm, key, iv, options)
            : crypto.createCipheriv(algorithm, key, null, options);
        cipher.setAutoPadding(true);

        // Get authentication tag for authenticated encryption modes
        let authTag = null;
        switch (mode) {
            /**
             * setAAD (optional) is only available for authenticated encryption modes GCM, CCM, OCB, and chacha20-poly1305
             */
            case 'gcm':
                {
                    const gcmCipher = cipher as crypto.CipherGCM;
                    gcmCipher.setAAD(Buffer.from(aad));
                    break;
                }
            case 'ccm':
                {
                    const ccmCipher = cipher as crypto.CipherCCM;
                    ccmCipher.setAAD(Buffer.from(aad), { plaintextLength: plainTextBufferLength });
                    break;
                }
            case 'ocb': {
                const ocbCipher = cipher as crypto.CipherOCB;
                ocbCipher.setAAD(Buffer.from(aad));
                break;
            }
        }

        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        switch (mode) {
            /**
             * getAuthTag (optional) is only available for authenticated encryption modes GCM, CCM, OCB, and chacha20-poly1305
             */
            case 'gcm':
                {
                    const gcmCipher = cipher as crypto.CipherGCM;
                    authTag = gcmCipher.getAuthTag();
                    break;
                }
            case 'ccm':
                {
                    const ccmCipher = cipher as crypto.CipherCCM;
                    authTag = ccmCipher.getAuthTag();
                    break;
                }
            case 'ocb': {
                const ocbCipher = cipher as crypto.CipherOCB;
                authTag = ocbCipher.getAuthTag();
                break;
            }
        }

        let result: any = {
            encrypted,
            algorithm
        }
        if (iv != null && iv != undefined) result = { ...result, iv: iv.toString('hex') };
        if (authTag != null && authTag != undefined) result = { ...result, authTag: authTag.toString('hex') };
        return result;
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        console.log(`Encryption failed ${algorithm}: ${errorMessage}`)
    }
}


function decryptAES(plaintextLength: number, ciphertext: any, iv: string | null, authTag: string | null, aad: string | null, mode: string, algorithm: string) {

    if (!ciphertext) {
        console.log('Encrypted data is required');
        return;
    }

    if (!modes.includes(mode as AESMode)) {
        console.log('Invalid mode');
        return;
    }

    try {
        const key = keys.get(algorithm);
        const ivBuffer = iv ? Buffer.from(iv, 'hex') : null;
        let options = getOptions(mode as AESMode, plaintextLength);

        const decipher = ivBuffer
            ? crypto.createDecipheriv(algorithm, key, ivBuffer, options)
            : crypto.createDecipheriv(algorithm, key, null, options);

        // Set authentication tag for authenticated encryption modes
        if (requiresAuth[mode as AESMode]) {
            if (!authTag) {
                throw new Error('Authentication tag is required for this mode');
            }
            switch (mode) {
                case 'gcm':
                    {
                        const decipherGCM = decipher as crypto.DecipherGCM;
                        decipherGCM.setAuthTag(Buffer.from(authTag, 'hex'));
                        if (aad != null || aad != undefined) decipherGCM.setAAD(Buffer.from(aad));
                        break;
                    }
                case 'ccm':
                    {
                        const decipherCCM = decipher as crypto.DecipherCCM;
                        decipherCCM.setAuthTag(Buffer.from(authTag, 'hex'));
                        if (aad != null || aad != undefined) decipherCCM.setAAD(Buffer.from(aad), { plaintextLength });
                        break;
                    }
                case 'ocb':
                    {
                        const decipherOCB = decipher as crypto.DecipherOCB;
                        decipherOCB.setAuthTag(Buffer.from(authTag, 'hex'));
                        if (aad != null || aad != undefined) decipherOCB.setAAD(Buffer.from(aad), { plaintextLength });
                        break;
                    }
            }

        }

        let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        const result = { decrypted, algorithm };
        return result;
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        console.log(`Decryption failed: ${errorMessage} ${algorithm}`)
    }
}

/*
modes.forEach(mode => {
    keySizes.forEach(size => {
        if (mode != 'xts' || size != 192) {
            const algorithm = `aes-${size}-${mode}`;
            const plaintext = 'Hello, World!123';
            const plaintextLength = Buffer.from(plaintext).length;
            let aad = "Additional data for authentication";
            const encryptedResult = encryptAES(plaintext, mode, algorithm, aad);
            const decryptedResult = decryptAES(plaintextLength, encryptedResult.encrypted, encryptedResult.iv, encryptedResult.authTag, aad, mode, algorithm);
            console.log(encryptedResult);
            console.log(decryptedResult);
        }
    })
})
*/

// Update the encryption endpoint AES
// app.post('/aes/:keySize/:mode/encrypt', express.json(), encryptAES);

// Update the decryption endpoint AES
// app.post('/aes/:keySize/:mode/decrypt', express.json(), decryptAES);


// 2. rsa encryption
type RSAOptions = {
    /**
    * Supported paddings:
    * ====================
    * crypto.constants.RSA_NO_PADDING
    * crypto.constants.RSA_PKCS1_PADDING
    * crypto.constants.RSA_PKCS1_OAEP_PADDING
    * crypto.constants.RSA_PKCS1_PSS_PADDING (for sign/verify)
    */
    padding?: number;
    /**
     * oaepHash specifies the hash function to use for OAEP padding.
     * Common values: 'sha1', 'sha256', 'sha384', 'sha512'.
     * Use a stronger hash (e.g., 'sha256' or above) for better security.
     * Only used when padding is RSA_PKCS1_OAEP_PADDING.
     */
    oaepHash?: string;
    passphrase?: string;
    /**
     * Optional label to associate with the encryption operation.
     * 
     * The `label` property is used only when the `padding` is set to `crypto.constants.RSA_PKCS1_OAEP_PADDING`.
     * It allows you to bind additional data to the encryption operation, which must be provided again during decryption.
     * This can be used to prevent certain types of attacks or to add context to the encrypted message.
     * 
     * If specified during encryption, the same label must be provided during decryption, or decryption will fail.
     * 
     * @example
     * ```typescript
     * const options: RSAOptions = {
     *   padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
     *   oaepHash: 'sha256',
     *   label: Buffer.from('my-app-context')
     * };
     * ```
     */
    label?: Buffer;
};

function encryptRSA(plaintext: string, publicKey: string | Buffer, options: RSAOptions = {}) {
    try {
        const encryptOptions = {
            key: publicKey,
            padding: options.padding ?? crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: options.oaepHash,
            passphrase: options.passphrase,
            oaepLabel: options.label
        };
        const encrypted = crypto.publicEncrypt(encryptOptions, Buffer.from(plaintext));
        return {
            encrypted: encrypted.toString('base64')
        };
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        console.log(`RSA encryption failed: ${errorMessage}`);
    }
}

function decryptRSA(ciphertext: string, privateKey: string | Buffer, options: RSAOptions = {}) {
    try {
        const decryptOptions = {
            key: privateKey,
            padding: options.padding ?? crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: options.oaepHash,
            passphrase: options.passphrase,
            oaepLabel: options.label
        };
        const decrypted = crypto.privateDecrypt(decryptOptions, Buffer.from(ciphertext, 'base64'));
        return {
            decrypted: decrypted.toString('utf8')
        };
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        console.log(`RSA decryption failed: ${errorMessage}`);
    }
}


const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'pkcs1',   // Key encoding type: 'pkcs1' (RSA-specific) or 'spki' (recommended for public keys)
        format: 'pem'    // Key encoding format: 'pem' (Base64 with header/footer) or 'der' (binary)
    },
    privateKeyEncoding: {
        type: 'pkcs1',   // Key encoding type: 'pkcs1' (RSA-specific) or 'pkcs8' (recommended for private keys)
        format: 'pem',   // Key encoding format: 'pem' or 'der'
        cipher: 'aes-256-cbc',      // Optional: encrypt the private key with this cipher
        passphrase: 'your-passphrase' // Passphrase for private key encryption
    }
})

try {
    const encRSA = encryptRSA("Hello, World RSA!", publicKey, {
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    });
    const decRSA = decryptRSA(encRSA!.encrypted, privateKey, {
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        passphrase: 'your-passphrase'
    });
    console.log(decRSA)
} catch (error) {
    console.log(`Error ${error}`);
}

/// base64

/// hash

/// certificate

/// different auth mode

// app.listen(port, () => {
//     console.log(`Server running at http://localhost:${port}`);
// });