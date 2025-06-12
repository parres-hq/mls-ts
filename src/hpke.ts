/**
 * HPKE (Hybrid Public Key Encryption) implementation per RFC 9180
 *
 * This implements the full HPKE specification needed for MLS, including:
 * - SetupBaseS/SetupBaseR for sender and receiver
 * - Proper KEM encapsulation/decapsulation
 * - Authenticated encryption with AEAD
 * - Context binding and export
 * - All required modes for MLS usage
 */

import type { CipherSuite } from "./types.ts";
import {
  aeadDecrypt,
  aeadEncrypt,
  getAEADParams,
  getCipherSuiteConfig,
  hkdfExpand,
  hkdfExtract,
  KEMID,
} from "./crypto.ts";
import type { AEADID as _AEADID, KDFID as _KDFID } from "./crypto.ts";
import { x25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";

// HPKE modes
export const HPKE_MODE_BASE = 0x00;
export const HPKE_MODE_PSK = 0x01;
export const HPKE_MODE_AUTH = 0x02;
export const HPKE_MODE_AUTH_PSK = 0x03;

// Default PSK and PSK_ID when not using PSK mode
const DEFAULT_PSK = new Uint8Array(0);
const DEFAULT_PSK_ID = new Uint8Array(0);

/**
 * HPKE Ciphertext - encapsulated key + ciphertext
 */
export interface HPKECiphertext {
  encappedKey: Uint8Array;
  ciphertext: Uint8Array;
}

/**
 * HPKE Context for encryption/decryption
 */
export interface HPKEContext {
  key: Uint8Array;
  baseNonce: Uint8Array;
  sequenceNumber: bigint;
  exporterSecret: Uint8Array;
  suite: CipherSuite;
}

/**
 * Get KEM shared secret length
 */
function getKEMSecretLength(kemId: KEMID): number {
  switch (kemId) {
    case KEMID.DHKEM_X25519_SHA256:
      return 32;
    case KEMID.DHKEM_P256_SHA256:
      return 32;
    case KEMID.DHKEM_P384_SHA384:
      return 48;
    case KEMID.DHKEM_P521_SHA512:
      return 64;
    default:
      throw new Error(`Unsupported KEM: ${kemId}`);
  }
}

/**
 * Perform Diffie-Hellman operation based on KEM
 */
function kemDH(
  kemId: KEMID,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): Uint8Array {
  switch (kemId) {
    case KEMID.DHKEM_X25519_SHA256:
      return x25519.getSharedSecret(privateKey, publicKey);
    case KEMID.DHKEM_P256_SHA256:
      return p256.getSharedSecret(privateKey, publicKey);
    case KEMID.DHKEM_P384_SHA384:
      return p384.getSharedSecret(privateKey, publicKey);
    case KEMID.DHKEM_P521_SHA512:
      return p521.getSharedSecret(privateKey, publicKey);
    default:
      throw new Error(`Unsupported KEM: ${kemId}`);
  }
}

/**
 * ExtractAndExpand operation from RFC 9180
 */
function extractAndExpand(
  suite: CipherSuite,
  dh: Uint8Array,
  kemContext: Uint8Array,
): Uint8Array {
  const config = getCipherSuiteConfig(suite);
  const secretLength = getKEMSecretLength(config.kem);

  // Extract
  const prk = hkdfExtract(suite, new Uint8Array(0), dh);

  // Expand with KEM context
  return hkdfExpand(suite, prk, kemContext, secretLength);
}

/**
 * Encapsulate - generate shared secret and encapsulated key
 */
function encapsulate(
  suite: CipherSuite,
  publicKeyR: Uint8Array,
): { sharedSecret: Uint8Array; encappedKey: Uint8Array } {
  const config = getCipherSuiteConfig(suite);

  // Generate ephemeral key pair
  let ephemeralPrivateKey: Uint8Array;
  let ephemeralPublicKey: Uint8Array;

  switch (config.kem) {
    case KEMID.DHKEM_X25519_SHA256:
      ephemeralPrivateKey = x25519.utils.randomPrivateKey();
      ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);
      break;
    case KEMID.DHKEM_P256_SHA256:
      ephemeralPrivateKey = p256.utils.randomPrivateKey();
      ephemeralPublicKey = p256.getPublicKey(ephemeralPrivateKey);
      break;
    case KEMID.DHKEM_P384_SHA384:
      ephemeralPrivateKey = p384.utils.randomPrivateKey();
      ephemeralPublicKey = p384.getPublicKey(ephemeralPrivateKey);
      break;
    case KEMID.DHKEM_P521_SHA512:
      ephemeralPrivateKey = p521.utils.randomPrivateKey();
      ephemeralPublicKey = p521.getPublicKey(ephemeralPrivateKey);
      break;
    default:
      throw new Error(`Unsupported KEM: ${config.kem}`);
  }

  // Perform DH
  const dh = kemDH(config.kem, ephemeralPrivateKey, publicKeyR);

  // Create KEM context
  const kemContext = new Uint8Array(
    ephemeralPublicKey.length + publicKeyR.length,
  );
  kemContext.set(ephemeralPublicKey, 0);
  kemContext.set(publicKeyR, ephemeralPublicKey.length);

  // Extract and expand
  const sharedSecret = extractAndExpand(suite, dh, kemContext);

  return {
    sharedSecret,
    encappedKey: ephemeralPublicKey,
  };
}

/**
 * Decapsulate - recover shared secret from encapsulated key
 */
function decapsulate(
  suite: CipherSuite,
  encappedKey: Uint8Array,
  privateKeyR: Uint8Array,
  publicKeyR: Uint8Array,
): Uint8Array {
  const config = getCipherSuiteConfig(suite);

  // Perform DH
  const dh = kemDH(config.kem, privateKeyR, encappedKey);

  // Create KEM context
  const kemContext = new Uint8Array(encappedKey.length + publicKeyR.length);
  kemContext.set(encappedKey, 0);
  kemContext.set(publicKeyR, encappedKey.length);

  // Extract and expand
  return extractAndExpand(suite, dh, kemContext);
}

/**
 * Create HPKE nonce for a given sequence number
 */
function computeNonce(baseNonce: Uint8Array, seq: bigint): Uint8Array {
  const nonce = new Uint8Array(baseNonce);

  // XOR the sequence number into the nonce (big-endian)
  let seqNum = seq;
  for (let i = nonce.length - 1; i >= 0 && seqNum > 0n; i--) {
    nonce[i] ^= Number(seqNum & 0xFFn);
    seqNum >>= 8n;
  }

  return nonce;
}

/**
 * Key schedule - derive key, base nonce, and exporter secret
 */
function keySchedule(
  suite: CipherSuite,
  mode: number,
  sharedSecret: Uint8Array,
  info: Uint8Array,
  psk: Uint8Array = DEFAULT_PSK,
  pskId: Uint8Array = DEFAULT_PSK_ID,
): { key: Uint8Array; baseNonce: Uint8Array; exporterSecret: Uint8Array } {
  const config = getCipherSuiteConfig(suite);
  const { keyLength, nonceLength } = getAEADParams(suite);

  // Build context
  const suiteId = new TextEncoder().encode("HPKE");
  const kemBytes = new Uint8Array(2);
  new DataView(kemBytes.buffer).setUint16(0, config.kem, false);
  const kdfBytes = new Uint8Array(2);
  new DataView(kdfBytes.buffer).setUint16(0, config.kdf, false);
  const aeadBytes = new Uint8Array(2);
  new DataView(aeadBytes.buffer).setUint16(0, config.aead, false);

  const hpkeSuiteId = new Uint8Array(
    suiteId.length + kemBytes.length + kdfBytes.length + aeadBytes.length,
  );
  hpkeSuiteId.set(suiteId, 0);
  hpkeSuiteId.set(kemBytes, suiteId.length);
  hpkeSuiteId.set(kdfBytes, suiteId.length + kemBytes.length);
  hpkeSuiteId.set(
    aeadBytes,
    suiteId.length + kemBytes.length + kdfBytes.length,
  );

  // Create PSK ID hash
  const pskIdHash = labeledExtract(
    suite,
    new Uint8Array(0),
    hpkeSuiteId,
    "psk_id_hash",
    pskId,
  );

  // Create info hash
  const infoHash = labeledExtract(
    suite,
    new Uint8Array(0),
    hpkeSuiteId,
    "info_hash",
    info,
  );

  // Create key schedule context
  const modeBytes = new Uint8Array(1);
  modeBytes[0] = mode;
  const keyScheduleContext = new Uint8Array(
    modeBytes.length + pskIdHash.length + infoHash.length,
  );
  keyScheduleContext.set(modeBytes, 0);
  keyScheduleContext.set(pskIdHash, modeBytes.length);
  keyScheduleContext.set(infoHash, modeBytes.length + pskIdHash.length);

  // Extract secret
  const secret = labeledExtract(
    suite,
    sharedSecret,
    hpkeSuiteId,
    "secret",
    psk,
  );

  // Derive key, base nonce, and exporter secret
  const key = labeledExpand(
    suite,
    secret,
    hpkeSuiteId,
    "key",
    keyScheduleContext,
    keyLength,
  );
  const baseNonce = labeledExpand(
    suite,
    secret,
    hpkeSuiteId,
    "base_nonce",
    keyScheduleContext,
    nonceLength,
  );
  const exporterSecret = labeledExpand(
    suite,
    secret,
    hpkeSuiteId,
    "exp",
    keyScheduleContext,
    config.hash.outputLen,
  );

  return { key, baseNonce, exporterSecret };
}

/**
 * Labeled extract function for HPKE
 */
function labeledExtract(
  suite: CipherSuite,
  salt: Uint8Array,
  suiteId: Uint8Array,
  label: string,
  ikm: Uint8Array,
): Uint8Array {
  const labeledIKM = buildLabeledInfo(suiteId, label, ikm);
  return hkdfExtract(suite, salt, labeledIKM);
}

/**
 * Labeled expand function for HPKE
 */
function labeledExpand(
  suite: CipherSuite,
  prk: Uint8Array,
  suiteId: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const labeledInfo = buildLabeledInfo(suiteId, label, info);
  return hkdfExpand(suite, prk, labeledInfo, length);
}

/**
 * Build labeled info for HPKE operations
 */
function buildLabeledInfo(
  suiteId: Uint8Array,
  label: string,
  info: Uint8Array,
): Uint8Array {
  const labelBytes = new TextEncoder().encode(label);
  const lengthBytes = new Uint8Array(2);
  new DataView(lengthBytes.buffer).setUint16(0, info.length, false);

  const versionLabel = new TextEncoder().encode("HPKE-v1");

  const result = new Uint8Array(
    versionLabel.length +
      suiteId.length +
      labelBytes.length +
      lengthBytes.length +
      info.length,
  );

  let offset = 0;
  result.set(versionLabel, offset);
  offset += versionLabel.length;
  result.set(suiteId, offset);
  offset += suiteId.length;
  result.set(labelBytes, offset);
  offset += labelBytes.length;
  result.set(lengthBytes, offset);
  offset += lengthBytes.length;
  result.set(info, offset);

  return result;
}

/**
 * SetupBaseS - HPKE sender setup for base mode
 */
export function setupBaseS(
  suite: CipherSuite,
  publicKeyR: Uint8Array,
  info: Uint8Array,
): { encappedKey: Uint8Array; context: HPKEContext } {
  // Encapsulate
  const { sharedSecret, encappedKey } = encapsulate(suite, publicKeyR);

  // Key schedule
  const { key, baseNonce, exporterSecret } = keySchedule(
    suite,
    HPKE_MODE_BASE,
    sharedSecret,
    info,
  );

  const context: HPKEContext = {
    key,
    baseNonce,
    sequenceNumber: 0n,
    exporterSecret,
    suite,
  };

  return { encappedKey, context };
}

/**
 * SetupBaseR - HPKE receiver setup for base mode
 */
export function setupBaseR(
  suite: CipherSuite,
  encappedKey: Uint8Array,
  privateKeyR: Uint8Array,
  publicKeyR: Uint8Array,
  info: Uint8Array,
): HPKEContext {
  // Decapsulate
  const sharedSecret = decapsulate(suite, encappedKey, privateKeyR, publicKeyR);

  // Key schedule
  const { key, baseNonce, exporterSecret } = keySchedule(
    suite,
    HPKE_MODE_BASE,
    sharedSecret,
    info,
  );

  return {
    key,
    baseNonce,
    sequenceNumber: 0n,
    exporterSecret,
    suite,
  };
}

/**
 * SetupPSKS - HPKE sender setup for PSK mode
 */
export function setupPSKS(
  suite: CipherSuite,
  publicKeyR: Uint8Array,
  info: Uint8Array,
  psk: Uint8Array,
  pskId: Uint8Array,
): { encappedKey: Uint8Array; context: HPKEContext } {
  // Encapsulate
  const { sharedSecret, encappedKey } = encapsulate(suite, publicKeyR);

  // Key schedule with PSK
  const { key, baseNonce, exporterSecret } = keySchedule(
    suite,
    HPKE_MODE_PSK,
    sharedSecret,
    info,
    psk,
    pskId,
  );

  const context: HPKEContext = {
    key,
    baseNonce,
    sequenceNumber: 0n,
    exporterSecret,
    suite,
  };

  return { encappedKey, context };
}

/**
 * SetupPSKR - HPKE receiver setup for PSK mode
 */
export function setupPSKR(
  suite: CipherSuite,
  encappedKey: Uint8Array,
  privateKeyR: Uint8Array,
  publicKeyR: Uint8Array,
  info: Uint8Array,
  psk: Uint8Array,
  pskId: Uint8Array,
): HPKEContext {
  // Decapsulate
  const sharedSecret = decapsulate(suite, encappedKey, privateKeyR, publicKeyR);

  // Key schedule with PSK
  const { key, baseNonce, exporterSecret } = keySchedule(
    suite,
    HPKE_MODE_PSK,
    sharedSecret,
    info,
    psk,
    pskId,
  );

  return {
    key,
    baseNonce,
    sequenceNumber: 0n,
    exporterSecret,
    suite,
  };
}

/**
 * Context.Seal - Encrypt with HPKE context
 */
export function contextSeal(
  context: HPKEContext,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  // Check sequence number overflow
  if (context.sequenceNumber >= (1n << 64n)) {
    throw new Error("HPKE sequence number overflow");
  }

  // Compute nonce
  const nonce = computeNonce(context.baseNonce, context.sequenceNumber);

  // Encrypt
  const ciphertext = aeadEncrypt(
    context.suite,
    context.key,
    nonce,
    plaintext,
    aad,
  );

  // Increment sequence number
  context.sequenceNumber++;

  return ciphertext;
}

/**
 * Context.Open - Decrypt with HPKE context
 */
export function contextOpen(
  context: HPKEContext,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  // Check sequence number overflow
  if (context.sequenceNumber >= (1n << 64n)) {
    throw new Error("HPKE sequence number overflow");
  }

  // Compute nonce
  const nonce = computeNonce(context.baseNonce, context.sequenceNumber);

  // Decrypt
  const plaintext = aeadDecrypt(
    context.suite,
    context.key,
    nonce,
    ciphertext,
    aad,
  );

  // Increment sequence number
  context.sequenceNumber++;

  return plaintext;
}

/**
 * Context.Export - Export secret from HPKE context
 */
export function contextExport(
  context: HPKEContext,
  exporterContext: Uint8Array,
  length: number,
): Uint8Array {
  const config = getCipherSuiteConfig(context.suite);

  // Build suite ID
  const suiteId = new TextEncoder().encode("HPKE");
  const kemBytes = new Uint8Array(2);
  new DataView(kemBytes.buffer).setUint16(0, config.kem, false);
  const kdfBytes = new Uint8Array(2);
  new DataView(kdfBytes.buffer).setUint16(0, config.kdf, false);
  const aeadBytes = new Uint8Array(2);
  new DataView(aeadBytes.buffer).setUint16(0, config.aead, false);

  const hpkeSuiteId = new Uint8Array(
    suiteId.length + kemBytes.length + kdfBytes.length + aeadBytes.length,
  );
  hpkeSuiteId.set(suiteId, 0);
  hpkeSuiteId.set(kemBytes, suiteId.length);
  hpkeSuiteId.set(kdfBytes, suiteId.length + kemBytes.length);
  hpkeSuiteId.set(
    aeadBytes,
    suiteId.length + kemBytes.length + kdfBytes.length,
  );

  return labeledExpand(
    context.suite,
    context.exporterSecret,
    hpkeSuiteId,
    "sec",
    exporterContext,
    length,
  );
}

/**
 * Single-shot encryption
 */
export function seal(
  suite: CipherSuite,
  publicKeyR: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): HPKECiphertext {
  const { encappedKey, context } = setupBaseS(suite, publicKeyR, info);
  const ciphertext = contextSeal(context, aad, plaintext);

  return { encappedKey, ciphertext };
}

/**
 * Single-shot decryption
 */
export function open(
  suite: CipherSuite,
  encappedKey: Uint8Array,
  privateKeyR: Uint8Array,
  publicKeyR: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const context = setupBaseR(suite, encappedKey, privateKeyR, publicKeyR, info);
  return contextOpen(context, aad, ciphertext);
}
