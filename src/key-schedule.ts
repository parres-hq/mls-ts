/**
 * Key schedule implementation for MLS
 * Based on RFC 9420 Section 8
 */

import {
  CipherSuite,
  type GroupContext,
  type PreSharedKeyID,
  type Secret,
} from "./types.ts";
import {
  deriveSecret,
  expandWithLabel,
  generateRandom,
  getCipherSuiteConfig,
  hkdfExtract,
} from "./crypto.ts";
import {
  encodeGroupContext,
  encodePreSharedKeyID,
  Encoder,
} from "./encoding.ts";
import { x25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";

/**
 * Epoch secrets derived from the key schedule
 */
export interface EpochSecrets {
  initSecret: Secret;
  senderDataSecret: Secret;
  encryptionSecret: Secret;
  exporterSecret: Secret;
  externalSecret: Secret;
  confirmationKey: Secret;
  membershipKey: Secret;
  resumptionPsk: Secret;
  epochAuthenticator: Secret;
}

/**
 * PSK with its extracted form
 */
export interface ExtractedPSK {
  id: PreSharedKeyID;
  secret: Secret;
}

/**
 * MLS Key Schedule
 */
export class KeySchedule {
  private suite: CipherSuite;
  private groupContext: GroupContext;
  private epochSecrets: EpochSecrets | null = null;
  private secretTree: SecretTree | null = null;
  private messageKeys: MessageKeys;

  constructor(suite: CipherSuite, groupContext: GroupContext) {
    this.suite = suite;
    this.groupContext = groupContext;
    this.messageKeys = new MessageKeys(suite);
  }

  /**
   * Initialize the key schedule for a new group (static factory method)
   */
  static init(suite: CipherSuite): KeySchedule {
    const initialContext: GroupContext = {
      protocolVersion: 0x0001, // MLS 1.0
      cipherSuite: suite,
      groupId: new Uint8Array(0),
      epoch: 0n,
      treeHash: new Uint8Array(0),
      confirmedTranscriptHash: new Uint8Array(0),
      extensions: [],
    };

    const keySchedule = new KeySchedule(suite, initialContext);
    keySchedule.initEpoch0();
    return keySchedule;
  }

  /**
   * Start a new epoch with commit secret
   */
  startEpoch(
    commitSecret: Uint8Array,
    psks?: ExtractedPSK[],
    newGroupContext?: GroupContext,
  ): Promise<void> {
    if (newGroupContext) {
      this.groupContext = newGroupContext;
    }

    if (this.groupContext.epoch === 0n) {
      this.initEpoch0();
    } else {
      this.nextEpoch(commitSecret, psks);
    }

    // Initialize secret tree for message encryption
    if (this.epochSecrets) {
      // For now, assume a fixed leaf count (should come from tree)
      const leafCount = 32; // This should be determined from the actual tree
      this.secretTree = new SecretTree(
        this.suite,
        this.epochSecrets.encryptionSecret,
        leafCount,
      );
    }
    return Promise.resolve();
  }

  /**
   * Get message keys for a generation
   */
  getMessageKeys(generation: bigint): Promise<{ key: Uint8Array; nonce: Uint8Array }> {
    // This is a simplified implementation
    // In a full implementation, this would derive keys from the secret tree
    if (!this.epochSecrets || !this.secretTree) {
      throw new Error("Key schedule not initialized");
    }

    // For now, return a simple derived key
    const genBytes = new Uint8Array(8);
    const view = new DataView(genBytes.buffer);
    view.setBigUint64(0, generation, false);

    const config = getCipherSuiteConfig(this.suite);
    const key = expandWithLabel(
      this.suite,
      this.epochSecrets.encryptionSecret,
      "msg",
      genBytes,
      config.aead === 0x0001 ? 16 : 32, // AES-128 or AES-256
    );

    const nonce = expandWithLabel(
      this.suite,
      this.epochSecrets.encryptionSecret,
      "nonce",
      genBytes,
      12, // All our AEADs use 12-byte nonces
    );

    return Promise.resolve({ key, nonce });
  }

  /**
   * Get confirmation tag
   */
  getConfirmationTag(): Uint8Array {
    if (!this.epochSecrets) {
      throw new Error("Key schedule not initialized");
    }

    // Simplified - should include transcript hash
    return expandWithLabel(
      this.suite,
      this.epochSecrets.confirmationKey,
      "confirmation",
      new Uint8Array(0),
      getCipherSuiteConfig(this.suite).hash.outputLen,
    );
  }

  /**
   * Get epoch authenticator
   */
  getEpochAuthenticator(): Uint8Array {
    if (!this.epochSecrets) {
      throw new Error("Key schedule not initialized");
    }

    return this.epochSecrets.epochAuthenticator;
  }

  /**
   * Get joiner secret for Welcome messages
   */
  getJoinerSecret(): Uint8Array {
    if (!this.epochSecrets) {
      throw new Error("Key schedule not initialized");
    }

    // Derive from init secret
    return deriveSecret(this.suite, this.epochSecrets.initSecret, "joiner");
  }

  /**
   * Initialize the key schedule for epoch 0
   */
  initEpoch0(): EpochSecrets {
    const config = getCipherSuiteConfig(this.suite);
    const hashLength = config.hash.outputLen;

    // For epoch 0, use random epoch secret
    const epochSecret = generateRandom(hashLength);

    // Derive all secrets
    this.epochSecrets = this.deriveEpochSecrets(
      new Uint8Array(hashLength), // zero init secret
      new Uint8Array(hashLength), // zero commit secret
      new Uint8Array(0), // empty PSK secret
      epochSecret,
    );

    return this.epochSecrets;
  }

  /**
   * Advance to next epoch
   */
  nextEpoch(
    commitSecret: Secret,
    psks?: ExtractedPSK[],
    forceInitSecret?: Secret,
  ): EpochSecrets {
    if (!this.epochSecrets) {
      throw new Error("Key schedule not initialized");
    }

    const initSecret = forceInitSecret || this.epochSecrets.initSecret;
    const pskSecret = psks ? this.computePSKSecret(psks) : new Uint8Array(0);

    // NOTE: Epoch is managed by the group context, not the key schedule
    // The caller should have already updated the group context epoch before calling this

    // Derive joiner secret
    const joinerSecret = hkdfExtract(this.suite, initSecret, commitSecret);
    const contextHash = encodeGroupContext(this.groupContext);
    const expandedJoiner = expandWithLabel(
      this.suite,
      joinerSecret,
      "joiner",
      contextHash,
      getCipherSuiteConfig(this.suite).hash.outputLen,
    );

    // Extract epoch secret
    const epochSecret = hkdfExtract(this.suite, pskSecret, expandedJoiner);
    const expandedEpoch = expandWithLabel(
      this.suite,
      epochSecret,
      "epoch",
      contextHash,
      getCipherSuiteConfig(this.suite).hash.outputLen,
    );

    // Derive all secrets
    this.epochSecrets = this.deriveEpochSecrets(
      initSecret,
      commitSecret,
      pskSecret,
      expandedEpoch,
    );

    return this.epochSecrets;
  }

  /**
   * Derive all epoch secrets
   */
  private deriveEpochSecrets(
    _initSecret: Secret,
    _commitSecret: Secret,
    _pskSecret: Secret,
    epochSecret: Secret,
  ): EpochSecrets {
    // Derive next init secret
    const nextInitSecret = deriveSecret(this.suite, epochSecret, "init");

    // Derive other secrets from epoch secret
    const senderDataSecret = deriveSecret(
      this.suite,
      epochSecret,
      "sender data",
    );
    const encryptionSecret = deriveSecret(
      this.suite,
      epochSecret,
      "encryption",
    );
    const exporterSecret = deriveSecret(this.suite, epochSecret, "exporter");
    const externalSecret = deriveSecret(this.suite, epochSecret, "external");
    const confirmationKey = deriveSecret(this.suite, epochSecret, "confirm");
    const membershipKey = deriveSecret(this.suite, epochSecret, "membership");
    const resumptionPsk = deriveSecret(this.suite, epochSecret, "resumption");
    const epochAuthenticator = deriveSecret(
      this.suite,
      epochSecret,
      "authentication",
    );

    return {
      initSecret: nextInitSecret,
      senderDataSecret,
      encryptionSecret,
      exporterSecret,
      externalSecret,
      confirmationKey,
      membershipKey,
      resumptionPsk,
      epochAuthenticator,
    };
  }

  /**
   * Compute PSK secret from a list of PSKs
   */
  private computePSKSecret(psks: ExtractedPSK[]): Secret {
    const config = getCipherSuiteConfig(this.suite);
    const hashLength = config.hash.outputLen;

    if (psks.length === 0) {
      return new Uint8Array(hashLength);
    }

    // Chain PSKs together
    let pskSecret = new Uint8Array(hashLength);

    for (let i = 0; i < psks.length; i++) {
      const psk = psks[i];

      // Extract PSK
      const extracted = hkdfExtract(
        this.suite,
        new Uint8Array(hashLength),
        psk.secret,
      );

      // Create PSK label
      const labelEncoder = new Encoder();
      labelEncoder.writeBytes(encodePreSharedKeyID(psk.id));
      labelEncoder.writeUint16(i);
      labelEncoder.writeUint16(psks.length);

      // Expand PSK
      const pskInput = expandWithLabel(
        this.suite,
        extracted,
        "derived psk",
        labelEncoder.finish(),
        hashLength,
      );

      // Chain with previous PSK secret
      const chained = hkdfExtract(this.suite, pskInput, pskSecret);
      pskSecret = new Uint8Array(chained);
    }

    return pskSecret;
  }

  /**
   * Derive exporter secret
   */
  export(label: string, _context: Uint8Array, length: number): Uint8Array {
    if (!this.epochSecrets) {
      throw new Error("Key schedule not initialized");
    }

    const secret = deriveSecret(
      this.suite,
      this.epochSecrets.exporterSecret,
      label,
    );
    const contextHash =
      this.suite === CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 ||
        this.suite === CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256 ||
        this.suite ===
          CipherSuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        ? new Uint8Array(32) // SHA256
        : this.suite === CipherSuite.MLS_256_DHKEMP384_AES256GCM_SHA384_P384
        ? new Uint8Array(48) // SHA384
        : new Uint8Array(64); // SHA512

    return expandWithLabel(this.suite, secret, "exported", contextHash, length);
  }

  /**
   * Get welcome secret for external joins
   */
  getWelcomeSecret(): Secret {
    if (!this.epochSecrets) {
      throw new Error("Key schedule not initialized");
    }

    // Derive welcome secret from joiner secret
    const config = getCipherSuiteConfig(this.suite);
    const hashLength = config.hash.outputLen;

    // For now, return a derived secret (should use joiner secret from commit)
    return deriveSecret(this.suite, this.epochSecrets.initSecret, "welcome");
  }

  /**
   * Export all epoch secrets for storage
   */
  exportSecrets(): EpochSecrets {
    if (!this.epochSecrets) {
      throw new Error("Key schedule not initialized");
    }
    return { ...this.epochSecrets };
  }

  /**
   * Get the current group context
   */
  getGroupContext(): GroupContext {
    return this.groupContext;
  }

  /**
   * Update the group context (e.g., after a commit)
   */
  updateGroupContext(context: GroupContext): void {
    this.groupContext = context;
  }

  /**
   * Compute the external HPKE key pair
   */
  getExternalKeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
    if (!this.epochSecrets) {
      throw new Error("Key schedule not initialized");
    }

    // Derive key pair from external secret
    const _config = getCipherSuiteConfig(this.suite);

    // For X25519
    if (
      this.suite === CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 ||
      this.suite ===
        CipherSuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    ) {
      const privateKey = this.epochSecrets.externalSecret.slice(0, 32);
      const publicKey = x25519.getPublicKey(privateKey);
      return { privateKey, publicKey };
    }

    // For P-256
    if (this.suite === CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256) {
      const privateKey = this.epochSecrets.externalSecret.slice(0, 32);
      const publicKey = p256.getPublicKey(privateKey);
      return { privateKey, publicKey };
    }

    // For P-384
    if (this.suite === CipherSuite.MLS_256_DHKEMP384_AES256GCM_SHA384_P384) {
      const privateKey = this.epochSecrets.externalSecret.slice(0, 48);
      const publicKey = p384.getPublicKey(privateKey);
      return { privateKey, publicKey };
    }

    // For P-521
    if (this.suite === CipherSuite.MLS_256_DHKEMP521_AES256GCM_SHA512_P521) {
      const privateKey = this.epochSecrets.externalSecret.slice(0, 66);
      const publicKey = p521.getPublicKey(privateKey);
      return { privateKey, publicKey };
    }

    throw new Error(`Unsupported cipher suite: ${this.suite}`);
  }
}

/**
 * Secret tree for message encryption
 */
export class SecretTree {
  private suite: CipherSuite;
  private encryptionSecret: Secret;
  private leafCount: number;
  private secrets: Map<number, Secret> = new Map();

  constructor(suite: CipherSuite, encryptionSecret: Secret, leafCount: number) {
    this.suite = suite;
    this.encryptionSecret = encryptionSecret;
    this.leafCount = leafCount;

    // Initialize root
    this.secrets.set(0, encryptionSecret);
  }

  /**
   * Get secret for a node
   */
  private getNodeSecret(index: number): Secret {
    if (this.secrets.has(index)) {
      return this.secrets.get(index)!;
    }

    // Derive from parent
    const parentIndex = Math.floor((index - 1) / 2);
    const parentSecret = this.getNodeSecret(parentIndex);

    const label = index % 2 === 1 ? "left" : "right";
    const secret = expandWithLabel(
      this.suite,
      parentSecret,
      label,
      new Uint8Array(0),
      getCipherSuiteConfig(this.suite).hash.outputLen,
    );

    this.secrets.set(index, secret);
    return secret;
  }

  /**
   * Get secret for a leaf
   */
  getLeafSecret(leafIndex: number): Secret {
    if (leafIndex >= this.leafCount) {
      throw new Error("Leaf index out of range");
    }

    // Convert to tree index (leaves start at leafCount - 1)
    const treeIndex = this.leafCount - 1 + leafIndex;
    return this.getNodeSecret(treeIndex);
  }

  /**
   * Derive handshake and application ratchet secrets
   */
  getRatchetSecrets(leafIndex: number): {
    handshakeSecret: Secret;
    applicationSecret: Secret;
  } {
    const leafSecret = this.getLeafSecret(leafIndex);

    const handshakeSecret = expandWithLabel(
      this.suite,
      leafSecret,
      "handshake",
      new Uint8Array(0),
      getCipherSuiteConfig(this.suite).hash.outputLen,
    );

    const applicationSecret = expandWithLabel(
      this.suite,
      leafSecret,
      "application",
      new Uint8Array(0),
      getCipherSuiteConfig(this.suite).hash.outputLen,
    );

    return { handshakeSecret, applicationSecret };
  }
}

/**
 * Message key derivation
 */
export class MessageKeys {
  private suite: CipherSuite;
  private handshakeKeys: Map<string, { key: Uint8Array; nonce: Uint8Array }> =
    new Map();
  private applicationKeys: Map<string, { key: Uint8Array; nonce: Uint8Array }> =
    new Map();

  constructor(suite: CipherSuite) {
    this.suite = suite;
  }

  /**
   * Derive key and nonce for a generation
   */
  deriveKeyNonce(
    secret: Secret,
    generation: number,
  ): { key: Uint8Array; nonce: Uint8Array } {
    const genBytes = new Uint8Array(4);
    new DataView(genBytes.buffer).setUint32(0, generation, false);

    const { keyLength, nonceLength } = this.getAEADParams();

    const key = expandWithLabel(
      this.suite,
      secret,
      "key",
      genBytes,
      keyLength,
    );

    const nonce = expandWithLabel(
      this.suite,
      secret,
      "nonce",
      genBytes,
      nonceLength,
    );

    // Derive next secret
    const _nextSecret = expandWithLabel(
      this.suite,
      secret,
      "secret",
      genBytes,
      getCipherSuiteConfig(this.suite).hash.outputLen,
    );

    return { key, nonce };
  }

  /**
   * Get AEAD parameters
   */
  private getAEADParams(): { keyLength: number; nonceLength: number } {
    const config = getCipherSuiteConfig(this.suite);

    switch (config.aead) {
      case 0x0001: // AES-128-GCM
        return { keyLength: 16, nonceLength: 12 };
      case 0x0002: // AES-256-GCM
        return { keyLength: 32, nonceLength: 12 };
      case 0x0003: // ChaCha20Poly1305
        return { keyLength: 32, nonceLength: 12 };
      default:
        throw new Error(`Unknown AEAD: ${config.aead}`);
    }
  }

  /**
   * Store derived keys
   */
  storeKeys(
    leafIndex: number,
    generation: number,
    isHandshake: boolean,
    key: Uint8Array,
    nonce: Uint8Array,
  ): void {
    const mapKey = `${leafIndex}-${generation}`;
    const map = isHandshake ? this.handshakeKeys : this.applicationKeys;
    map.set(mapKey, { key, nonce });
  }

  /**
   * Get stored keys
   */
  getKeys(
    leafIndex: number,
    generation: number,
    isHandshake: boolean,
  ): { key: Uint8Array; nonce: Uint8Array } | undefined {
    const mapKey = `${leafIndex}-${generation}`;
    const map = isHandshake ? this.handshakeKeys : this.applicationKeys;
    return map.get(mapKey);
  }

  /**
   * Delete used keys
   */
  deleteKeys(
    leafIndex: number,
    generation: number,
    isHandshake: boolean,
  ): void {
    const mapKey = `${leafIndex}-${generation}`;
    const map = isHandshake ? this.handshakeKeys : this.applicationKeys;
    map.delete(mapKey);
  }
}
