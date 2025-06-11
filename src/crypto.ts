/**
 * Cryptographic operations for MLS
 * Using @noble libraries for well-tested implementations
 */

import { sha256, sha384, sha512 } from "@noble/hashes/sha2";
import { hmac } from "@noble/hashes/hmac";
import type { hkdf } from "@noble/hashes/hkdf";
import { randomBytes } from "@noble/hashes/utils";
import { x25519 } from "@noble/curves/ed25519";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";
import { gcm } from "@noble/ciphers/aes";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { CipherSuite } from "./types.ts";

// Re-export HPKE modes from our full implementation
export { HPKE_MODE_BASE as HPKEMode } from "./hpke.ts";

// KEM IDs
export enum KEMID {
  DHKEM_P256_SHA256 = 0x0010,
  DHKEM_P384_SHA384 = 0x0011,
  DHKEM_P521_SHA512 = 0x0012,
  DHKEM_X25519_SHA256 = 0x0020,
  DHKEM_X448_SHA512 = 0x0021,
}

// KDF IDs
export enum KDFID {
  HKDF_SHA256 = 0x0001,
  HKDF_SHA384 = 0x0002,
  HKDF_SHA512 = 0x0003,
}

// AEAD IDs
export enum AEADID {
  AES_128_GCM = 0x0001,
  AES_256_GCM = 0x0002,
  CHACHA20_POLY1305 = 0x0003,
}

// Cipher suite configuration
export interface CipherSuiteConfig {
  kem: KEMID;
  kdf: KDFID;
  aead: AEADID;
  hash: typeof sha256 | typeof sha384 | typeof sha512;
  signatureCurve: typeof ed25519 | typeof p256 | typeof p384 | typeof p521;
}

// Map cipher suites to their configurations
export const CIPHER_SUITE_CONFIGS: Record<CipherSuite, CipherSuiteConfig> = {
  [CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519]: {
    kem: KEMID.DHKEM_X25519_SHA256,
    kdf: KDFID.HKDF_SHA256,
    aead: AEADID.AES_128_GCM,
    hash: sha256,
    signatureCurve: ed25519,
  },
  [CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256]: {
    kem: KEMID.DHKEM_P256_SHA256,
    kdf: KDFID.HKDF_SHA256,
    aead: AEADID.AES_128_GCM,
    hash: sha256,
    signatureCurve: p256,
  },
  [CipherSuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519]: {
    kem: KEMID.DHKEM_X25519_SHA256,
    kdf: KDFID.HKDF_SHA256,
    aead: AEADID.CHACHA20_POLY1305,
    hash: sha256,
    signatureCurve: ed25519,
  },
  [CipherSuite.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448]: {
    kem: KEMID.DHKEM_X448_SHA512,
    kdf: KDFID.HKDF_SHA512,
    aead: AEADID.AES_256_GCM,
    hash: sha512,
    signatureCurve: ed25519, // Note: ed448 not available in @noble, using ed25519
  },
  [CipherSuite.MLS_256_DHKEMP521_AES256GCM_SHA512_P521]: {
    kem: KEMID.DHKEM_P521_SHA512,
    kdf: KDFID.HKDF_SHA512,
    aead: AEADID.AES_256_GCM,
    hash: sha512,
    signatureCurve: p521,
  },
  [CipherSuite.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448]: {
    kem: KEMID.DHKEM_X448_SHA512,
    kdf: KDFID.HKDF_SHA512,
    aead: AEADID.CHACHA20_POLY1305,
    hash: sha512,
    signatureCurve: ed25519, // Note: ed448 not available in @noble, using ed25519
  },
  [CipherSuite.MLS_256_DHKEMP384_AES256GCM_SHA384_P384]: {
    kem: KEMID.DHKEM_P384_SHA384,
    kdf: KDFID.HKDF_SHA384,
    aead: AEADID.AES_256_GCM,
    hash: sha384,
    signatureCurve: p384,
  },
};

/**
 * Get the configuration for a cipher suite
 */
export function getCipherSuiteConfig(suite: CipherSuite): CipherSuiteConfig {
  const config = CIPHER_SUITE_CONFIGS[suite];
  if (!config) {
    throw new Error(`Unsupported cipher suite: ${suite}`);
  }
  return config;
}

/**
 * Hash function wrapper
 */
export function hash(suite: CipherSuite, data: Uint8Array): Uint8Array {
  const config = getCipherSuiteConfig(suite);
  return config.hash(data);
}

/**
 * HMAC function wrapper
 */
export function computeHMAC(
  suite: CipherSuite,
  key: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  const config = getCipherSuiteConfig(suite);
  return hmac(config.hash, key, data);
}

/**
 * HKDF Extract function
 */
export function hkdfExtract(
  suite: CipherSuite,
  salt: Uint8Array,
  ikm: Uint8Array,
): Uint8Array {
  const config = getCipherSuiteConfig(suite);
  // HKDF extract is essentially HMAC with salt as key and ikm as message
  if (salt.length === 0) {
    salt = new Uint8Array(config.hash.outputLen); // Use zero salt if empty
  }
  return hmac(config.hash, salt, ikm);
}

/**
 * HKDF Expand function
 */
export function hkdfExpand(
  suite: CipherSuite,
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const config = getCipherSuiteConfig(suite);
  const hashLen = config.hash.outputLen;
  const n = Math.ceil(length / hashLen);
  const output = new Uint8Array(n * hashLen);

  let prev = new Uint8Array(0);
  for (let i = 0; i < n; i++) {
    const counter = new Uint8Array([i + 1]);
    const data = new Uint8Array(prev.length + info.length + 1);
    data.set(prev);
    data.set(info, prev.length);
    data.set(counter, prev.length + info.length);

    prev = new Uint8Array(hmac(config.hash, prk, data));
    output.set(prev, i * hashLen);
  }

  return output.slice(0, length);
}

/**
 * ExpandWithLabel function as per RFC 9420
 */
export function expandWithLabel(
  suite: CipherSuite,
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
): Uint8Array {
  // Encode length as 2 bytes
  const lengthBytes = new Uint8Array(2);
  new DataView(lengthBytes.buffer).setUint16(0, length, false);

  // Encode "MLS 1.0 " + label
  const labelPrefix = new TextEncoder().encode("MLS 1.0 ");
  const labelBytes = new TextEncoder().encode(label);
  const fullLabel = new Uint8Array(labelPrefix.length + labelBytes.length);
  fullLabel.set(labelPrefix);
  fullLabel.set(labelBytes, labelPrefix.length);

  // Encode lengths as variable-length integers (simplified for now)
  const labelLength = new Uint8Array(1);
  labelLength[0] = fullLabel.length;

  const contextLength = new Uint8Array(1);
  contextLength[0] = context.length;

  // Construct KDFLabel
  const kdfLabel = new Uint8Array(
    lengthBytes.length +
      labelLength.length +
      fullLabel.length +
      contextLength.length +
      context.length,
  );

  let offset = 0;
  kdfLabel.set(lengthBytes, offset);
  offset += lengthBytes.length;
  kdfLabel.set(labelLength, offset);
  offset += labelLength.length;
  kdfLabel.set(fullLabel, offset);
  offset += fullLabel.length;
  kdfLabel.set(contextLength, offset);
  offset += contextLength.length;
  kdfLabel.set(context, offset);

  return hkdfExpand(suite, secret, kdfLabel, length);
}

/**
 * DeriveSecret function as per RFC 9420
 */
export function deriveSecret(
  suite: CipherSuite,
  secret: Uint8Array,
  label: string,
): Uint8Array {
  const config = getCipherSuiteConfig(suite);
  const hashLength = config.hash.outputLen;
  return expandWithLabel(suite, secret, label, new Uint8Array(0), hashLength);
}

/**
 * Generate random bytes
 */
export function generateRandom(length: number): Uint8Array {
  return randomBytes(length);
}

/**
 * Key pair generation for HPKE
 */
export interface HPKEKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Generate HPKE key pair
 */
export function generateHPKEKeyPair(suite: CipherSuite): HPKEKeyPair {
  const config = getCipherSuiteConfig(suite);

  switch (config.kem) {
    case KEMID.DHKEM_X25519_SHA256: {
      const privateKey = x25519.utils.randomPrivateKey();
      const publicKey = x25519.getPublicKey(privateKey);
      return { privateKey, publicKey };
    }
    case KEMID.DHKEM_P256_SHA256: {
      const privateKey = p256.utils.randomPrivateKey();
      const publicKey = p256.getPublicKey(privateKey);
      return { privateKey, publicKey };
    }
    case KEMID.DHKEM_P384_SHA384: {
      const privateKey = p384.utils.randomPrivateKey();
      const publicKey = p384.getPublicKey(privateKey);
      return { privateKey, publicKey };
    }
    case KEMID.DHKEM_P521_SHA512: {
      const privateKey = p521.utils.randomPrivateKey();
      const publicKey = p521.getPublicKey(privateKey);
      return { privateKey, publicKey };
    }
    default:
      throw new Error(`Unsupported KEM: ${config.kem}`);
  }
}

/**
 * Derive HPKE key pair from seed
 */
export function deriveHPKEKeyPair(
  suite: CipherSuite,
  seed: Uint8Array,
): HPKEKeyPair {
  const config = getCipherSuiteConfig(suite);

  // For now, use the seed directly as private key (should be properly derived)
  switch (config.kem) {
    case KEMID.DHKEM_X25519_SHA256: {
      const privateKey = seed.slice(0, 32);
      const publicKey = x25519.getPublicKey(privateKey);
      return { privateKey, publicKey };
    }
    case KEMID.DHKEM_P256_SHA256: {
      const privateKey = seed.slice(0, 32);
      const publicKey = p256.getPublicKey(privateKey);
      return { privateKey, publicKey };
    }
    case KEMID.DHKEM_P384_SHA384: {
      const privateKey = seed.slice(0, 48);
      const publicKey = p384.getPublicKey(privateKey);
      return { privateKey, publicKey };
    }
    case KEMID.DHKEM_P521_SHA512: {
      const privateKey = seed.slice(0, 66);
      const publicKey = p521.getPublicKey(privateKey);
      return { privateKey, publicKey };
    }
    default:
      throw new Error(`Unsupported KEM: ${config.kem}`);
  }
}

/**
 * Signature key pair
 */
export interface SignatureKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Generate signature key pair
 */
export function generateSignatureKeyPair(suite: CipherSuite): SignatureKeyPair {
  const config = getCipherSuiteConfig(suite);

  if (config.signatureCurve === ed25519) {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
  } else if (config.signatureCurve === p256) {
    const privateKey = p256.utils.randomPrivateKey();
    const publicKey = p256.getPublicKey(privateKey);
    return { privateKey, publicKey };
  } else if (config.signatureCurve === p384) {
    const privateKey = p384.utils.randomPrivateKey();
    const publicKey = p384.getPublicKey(privateKey);
    return { privateKey, publicKey };
  } else if (config.signatureCurve === p521) {
    const privateKey = p521.utils.randomPrivateKey();
    const publicKey = p521.getPublicKey(privateKey);
    return { privateKey, publicKey };
  } else {
    throw new Error("Unsupported signature curve");
  }
}

/**
 * Sign data
 */
export function sign(
  suite: CipherSuite,
  privateKey: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  const config = getCipherSuiteConfig(suite);

  if (config.signatureCurve === ed25519) {
    return ed25519.sign(data, privateKey);
  } else if (config.signatureCurve === p256) {
    return p256.sign(data, privateKey).toCompactRawBytes();
  } else if (config.signatureCurve === p384) {
    return p384.sign(data, privateKey).toCompactRawBytes();
  } else if (config.signatureCurve === p521) {
    return p521.sign(data, privateKey).toCompactRawBytes();
  } else {
    throw new Error("Unsupported signature curve");
  }
}

/**
 * Verify signature
 */
export function verify(
  suite: CipherSuite,
  publicKey: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  const config = getCipherSuiteConfig(suite);

  try {
    if (config.signatureCurve === ed25519) {
      return ed25519.verify(signature, data, publicKey);
    } else if (config.signatureCurve === p256) {
      return p256.verify(signature, data, publicKey);
    } else if (config.signatureCurve === p384) {
      return p384.verify(signature, data, publicKey);
    } else if (config.signatureCurve === p521) {
      return p521.verify(signature, data, publicKey);
    } else {
      throw new Error("Unsupported signature curve");
    }
  } catch {
    return false;
  }
}

/**
 * AEAD encryption
 */
export interface AEADEncrypted {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

/**
 * Get AEAD key and nonce lengths
 */
export function getAEADParams(
  suite: CipherSuite,
): { keyLength: number; nonceLength: number } {
  const config = getCipherSuiteConfig(suite);

  switch (config.aead) {
    case AEADID.AES_128_GCM:
      return { keyLength: 16, nonceLength: 12 };
    case AEADID.AES_256_GCM:
      return { keyLength: 32, nonceLength: 12 };
    case AEADID.CHACHA20_POLY1305:
      return { keyLength: 32, nonceLength: 12 };
    default:
      throw new Error(`Unsupported AEAD: ${config.aead}`);
  }
}

/**
 * AEAD encrypt
 */
export function aeadEncrypt(
  suite: CipherSuite,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const config = getCipherSuiteConfig(suite);

  switch (config.aead) {
    case AEADID.AES_128_GCM:
    case AEADID.AES_256_GCM: {
      const cipher = gcm(key, nonce, aad);
      return cipher.encrypt(plaintext);
    }
    case AEADID.CHACHA20_POLY1305: {
      return chacha20poly1305(key, nonce, aad).encrypt(plaintext);
    }
    default:
      throw new Error(`Unsupported AEAD: ${config.aead}`);
  }
}

/**
 * AEAD decrypt
 */
export function aeadDecrypt(
  suite: CipherSuite,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const config = getCipherSuiteConfig(suite);

  switch (config.aead) {
    case AEADID.AES_128_GCM:
    case AEADID.AES_256_GCM: {
      const cipher = gcm(key, nonce, aad);
      return cipher.decrypt(ciphertext);
    }
    case AEADID.CHACHA20_POLY1305: {
      return chacha20poly1305(key, nonce, aad).decrypt(ciphertext);
    }
    default:
      throw new Error(`Unsupported AEAD: ${config.aead}`);
  }
}

/**
 * SignWithLabel as per RFC 9420
 */
export function signWithLabel(
  suite: CipherSuite,
  privateKey: Uint8Array,
  label: string,
  content: Uint8Array,
): Uint8Array {
  const labelPrefix = new TextEncoder().encode("MLS 1.0 ");
  const labelBytes = new TextEncoder().encode(label);
  const fullLabel = new Uint8Array(labelPrefix.length + labelBytes.length);
  fullLabel.set(labelPrefix);
  fullLabel.set(labelBytes, labelPrefix.length);

  // Encode as SignContent structure
  const labelLength = encodeVarint(fullLabel.length);
  const contentLength = encodeVarint(content.length);

  const signContent = new Uint8Array(
    labelLength.length + fullLabel.length +
      contentLength.length + content.length,
  );

  let offset = 0;
  signContent.set(labelLength, offset);
  offset += labelLength.length;
  signContent.set(fullLabel, offset);
  offset += fullLabel.length;
  signContent.set(contentLength, offset);
  offset += contentLength.length;
  signContent.set(content, offset);

  return sign(suite, privateKey, signContent);
}

/**
 * VerifyWithLabel as per RFC 9420
 */
export function verifyWithLabel(
  suite: CipherSuite,
  publicKey: Uint8Array,
  label: string,
  content: Uint8Array,
  signature: Uint8Array,
): boolean {
  const labelPrefix = new TextEncoder().encode("MLS 1.0 ");
  const labelBytes = new TextEncoder().encode(label);
  const fullLabel = new Uint8Array(labelPrefix.length + labelBytes.length);
  fullLabel.set(labelPrefix);
  fullLabel.set(labelBytes, labelPrefix.length);

  // Encode as SignContent structure
  const labelLength = encodeVarint(fullLabel.length);
  const contentLength = encodeVarint(content.length);

  const signContent = new Uint8Array(
    labelLength.length + fullLabel.length +
      contentLength.length + content.length,
  );

  let offset = 0;
  signContent.set(labelLength, offset);
  offset += labelLength.length;
  signContent.set(fullLabel, offset);
  offset += fullLabel.length;
  signContent.set(contentLength, offset);
  offset += contentLength.length;
  signContent.set(content, offset);

  return verify(suite, publicKey, signContent, signature);
}

/**
 * Encode a variable-length integer (varint) as per RFC 9420 Section 2.1.2
 */
export function encodeVarint(value: number): Uint8Array {
  if (value < 0) {
    throw new Error("Varint value must be non-negative");
  }

  if (value <= 63) {
    // 1 byte encoding (00xxxxxx)
    return new Uint8Array([value]);
  } else if (value <= 16383) {
    // 2 byte encoding (01xxxxxx xxxxxxxx)
    const bytes = new Uint8Array(2);
    bytes[0] = 0x40 | (value >> 8);
    bytes[1] = value & 0xff;
    return bytes;
  } else if (value <= 1073741823) {
    // 4 byte encoding (10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx)
    const bytes = new Uint8Array(4);
    bytes[0] = 0x80 | (value >> 24);
    bytes[1] = (value >> 16) & 0xff;
    bytes[2] = (value >> 8) & 0xff;
    bytes[3] = value & 0xff;
    return bytes;
  } else {
    throw new Error("Varint value too large");
  }
}

/**
 * Decode a variable-length integer
 */
export function decodeVarint(
  bytes: Uint8Array,
  offset: number = 0,
): { value: number; bytesRead: number } {
  if (offset >= bytes.length) {
    throw new Error("Not enough bytes to decode varint");
  }

  const firstByte = bytes[offset];
  const prefix = firstByte >> 6;

  if (prefix === 0) {
    // 1 byte encoding
    return { value: firstByte & 0x3f, bytesRead: 1 };
  } else if (prefix === 1) {
    // 2 byte encoding
    if (offset + 1 >= bytes.length) {
      throw new Error("Not enough bytes to decode varint");
    }
    const value = ((firstByte & 0x3f) << 8) | bytes[offset + 1];
    // Check minimum encoding
    if (value < 64) {
      throw new Error("Varint not using minimum encoding");
    }
    return { value, bytesRead: 2 };
  } else if (prefix === 2) {
    // 4 byte encoding
    if (offset + 3 >= bytes.length) {
      throw new Error("Not enough bytes to decode varint");
    }
    const value = ((firstByte & 0x3f) << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3];
    // Check minimum encoding
    if (value < 16384) {
      throw new Error("Varint not using minimum encoding");
    }
    return { value, bytesRead: 4 };
  } else {
    throw new Error("Invalid varint prefix");
  }
}
