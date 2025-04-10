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
    'cbc',  // Cipher Block Chaining
    'ccm',  // Counter with CBC-MAC
    'cfb',  // Cipher Feedback
    'ctr',  // Counter
    'ecb',  // Electronic Codebook
    'gcm',  // Galois/Counter Mode
    'ige',  // Infinite Garble Extension
    'ocb',  // Offset Codebook Mode
    'ofb',  // Output Feedback
    'sic',  // Segmented Integer Counter (alias for CTR)
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
    'ige': true,
    'ocb': true,
    'ofb': true,
    'sic': true
};

// Define which modes require authentication tag
const requiresAuth: Record<AESMode, boolean> = {
    'cbc': false,
    'ccm': true,
    'cfb': false,
    'ctr': false,
    'ecb': false,
    'gcm': true,
    'ige': false,
    'ocb': true,
    'ofb': false,
    'sic': true,
};

// Add IGE encryption function
function encryptIGE(plaintext: Buffer, key: Buffer, iv: Buffer): Buffer {
    const blockSize = 16; // AES block size
    const blocks = Math.ceil(plaintext.length / blockSize);
    const result = Buffer.alloc(blocks * blockSize);
    
    let prevCiphertext = iv.subarray(0, blockSize);
    let prevPlaintext = iv.subarray(blockSize);
    
    for (let i = 0; i < blocks; i++) {
        const block = plaintext.subarray(i * blockSize, (i + 1) * blockSize);
        const xoredBlock = Buffer.alloc(blockSize);
        
        // XOR with previous ciphertext
        for (let j = 0; j < blockSize; j++) {
            xoredBlock[j] = block[j] ^ prevCiphertext[j];
        }
        
        // Encrypt
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        cipher.setAutoPadding(true);
        const encrypted = cipher.update(xoredBlock);
        
        // XOR with previous plaintext
        for (let j = 0; j < blockSize; j++) {
            result[i * blockSize + j] = encrypted[j] ^ prevPlaintext[j];
        }
        
        prevCiphertext = result.subarray(i * blockSize, (i + 1) * blockSize);
        prevPlaintext = block;
    }
    
    return result;
}

// Add IGE decryption function
function decryptIGE(ciphertext: Buffer, key: Buffer, iv: Buffer): Buffer {
    const blockSize = 16;
    const blocks = Math.ceil(ciphertext.length / blockSize);
    const result = Buffer.alloc(blocks * blockSize);
    
    let prevCiphertext = iv.subarray(0, blockSize);
    let prevPlaintext = iv.subarray(blockSize);
    
    for (let i = 0; i < blocks; i++) {
        const block = ciphertext.subarray(i * blockSize, (i + 1) * blockSize);
        const xoredBlock = Buffer.alloc(blockSize);
        
        // XOR with previous plaintext
        for (let j = 0; j < blockSize; j++) {
            xoredBlock[j] = block[j] ^ prevPlaintext[j];
        }
        
        // Decrypt
        const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
        decipher.setAutoPadding(false);
        const decrypted = decipher.update(xoredBlock);
        
        // XOR with previous ciphertext
        for (let j = 0; j < blockSize; j++) {
            result[i * blockSize + j] = decrypted[j] ^ prevCiphertext[j];
        }
        
        prevCiphertext = block;
        prevPlaintext = result.subarray(i * blockSize, (i + 1) * blockSize);
    }
    
    return result;
}

// Initialize keys and IVs for each combination
modes.forEach(mode => {
    keySizes.forEach(size => {
        const keyId = `aes-${size}-${mode}`;
        keys.set(keyId, crypto.randomBytes(size / 8));
    });
});

// Update the encryption endpoint
app.post('/aes/:keySize/:mode/encrypt', express.json(), (req: Request, res: Response): void => {
    const { plaintext } = req.body;
    const { keySize, mode } = req.params;
    let algorithm = `aes-${keySize}-${mode}`;

    if (!plaintext) {
        res.status(400).send({ error: 'Plaintext is required' });
        return;
    }

    if (!modes.includes(mode as AESMode)) {
        res.status(400).send({ error: 'Invalid mode' });
        return;
    }

    if (mode === 'sic') {
        algorithm = `aes-${keySize}-ctr`;
    }

    try {
        const key = keys.get(algorithm);
        const iv = requiresIV[mode as AESMode] ? crypto.randomBytes(16) : null;
        
        const cipher = iv
            ? crypto.createCipheriv(algorithm, key, iv)
            : crypto.createCipheriv(algorithm, key, null);

        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        // Get authentication tag for authenticated encryption modes
        const authTag = requiresAuth[mode as AESMode] && 'getAuthTag' in cipher ? (cipher as crypto.CipherGCM).getAuthTag() : null;

        res.send({
            encrypted,
            iv: iv ? iv.toString('hex') : null,
            authTag: authTag ? authTag.toString('hex') : null,
            algorithm
        });
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        res.status(400).send({ error: `Encryption failed: ${errorMessage}` });
    }
});

// Update the decryption endpoint
app.post('/aes/:keySize/:mode/decrypt', express.json(), (req: Request, res: Response): void => {
    const { encrypted, iv, authTag } = req.body;
    const { keySize, mode } = req.params;
    let algorithm = `aes-${keySize}-${mode}`;

    if (!encrypted) {
        res.status(400).send({ error: 'Encrypted text is required' });
        return;
    }

    if (!modes.includes(mode as AESMode)) {
        res.status(400).send({ error: 'Invalid mode' });
        return;
    }

    if (mode === 'sic') {
        algorithm = `aes-${keySize}-ctr`;
    }

    try {
        const key = keys.get(algorithm);
        const ivBuffer = iv ? Buffer.from(iv, 'hex') : null;
        
        const decipher = ivBuffer
            ? crypto.createDecipheriv(algorithm, key, ivBuffer)
            : crypto.createDecipheriv(algorithm, key, null);

        // Set authentication tag for authenticated encryption modes
        if (requiresAuth[mode as AESMode]) {
            if (!authTag) {
                throw new Error('Authentication tag is required for this mode');
            }
            (decipher as crypto.DecipherGCM).setAuthTag(Buffer.from(authTag, 'hex'));
        }

        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        res.send({ decrypted, algorithm });
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        res.status(400).send({ error: `Decryption failed: ${errorMessage}` });
    }
});
// 2. rsa encryption

/// base64

/// hash

/// certificate

/// different auth mode

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});