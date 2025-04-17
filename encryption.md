## AES (Advanced Encryption Standard)

> Symmetric block cipher encryption

### Parameters:
#### 1. Secret Key
* Key Sizes:
    + AES-128 (128 bits): 10 rounds
    + AES-192 (192 bits): 12 rounds
    + AES-256 (256 bits): 14 rounds (each round: the SubBytes, ShiftRows, MixColumns (except the last round), AddRoundKey)
#### 2. Plain Text / Cipher Text
#### 3. Initialization Vector (IV) / Nonce: 
* IV: Non-secret random value that is used with certain mode of operations (should be unique for each encryption to prevent attack) like CBC, CTR, GCM
* Nonce (Number used once): crucial for mode GCM and CTR the value must be unique for each encryption
* Size of IV/nonce depends on mode of operations like 16 bytes for CBC 128 bits AES

#### 4. Mode of Operation
* **ECB (Electronic Codebook)**: simple but generally insecure as identical plaintext blocks produce identical cipertext blocks
* **CBC (Cipher Block Chaining)**: each plaintext block is XORed with previous ciphertext block before encryption (REQUIRED IV)
* **CTR (Counter)**: treat AES as a stream cipher by encrypting a counter value then XORing it with the plaintext (REQUIRED UNIQUE NONCE)
* **GCM (Galois/Counter Mode)**: provide both confidentiality (using CTR) and data authenticity and integrity (using GMAC) (REQUIRED A UNIQUE NONCE)
* **CFB (Cipher Feedback)**: operate like a stream cipher, where previous ciphertext block is encrypted then XORed with the current plaintext block (REQUIRE an IV)
* **OFB (Output Feedback)**: generate a keystream by iteratively encrypting the IV. The keystream is then XORed with the plaintext (REQUIRE A UNIQUE IV)
#### 5. Padding
* AES operates on fixed-size blocks, if plaintext is not a multiple of the block size (128 bits), padding is applied to make it a multiple.
* Common padding schemes include PKCS#7 padding. Modes like **CTR** and **GCM** do not require padding as they effectively turn the block cipher into a stream cipher
#### 6. Associated Authenticated Data (AAD) for AEAD modes like GCM
* This is optional data you want to authenticate for integrity but do not need to encrypt (e.g. headers, metadata, ...)
* It must be provided during decryption for authentication to succeed