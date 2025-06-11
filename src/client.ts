/**
 * MLS Client Management
 * Handles client initialization, KeyPackage generation and management
 */

import {
  type Capabilities,
  CipherSuite,
  type Credential,
  CredentialType,
  type ExtensionType,
  type KeyPackage,
  type KeyPackageRef,
  type LeafNode,
  LeafNodeSource,
  type Lifetime,
  ProtocolVersion,
} from "./types.ts";

import {
  generateHPKEKeyPair,
  generateSignatureKeyPair,
  hash,
  signWithLabel,
} from "./crypto.ts";

import {
  encodeKeyPackage,
  encodeKeyPackageTBS,
  encodeLeafNodeTBS,
} from "./encoding.ts";
import {
  MLSStorage,
  type StoredKeyPackage as StoredKeyPackageType,
} from "./storage.ts";
import { InMemoryMLSStorage } from "./storage-memory.ts";

export interface ClientConfig {
  identity: Uint8Array;
  credentialType?: CredentialType;
  supportedCipherSuites?: CipherSuite[];
  supportedVersions?: ProtocolVersion[];
  supportedExtensions?: ExtensionType[];
  lifetimeInSeconds?: number;
  storage?: MLSStorage;
}

export class MLSClient {
  private identity: Uint8Array;
  private credentialType: CredentialType;
  private supportedCipherSuites: CipherSuite[];
  private supportedVersions: ProtocolVersion[];
  private supportedExtensions: ExtensionType[];
  private lifetimeInSeconds: number;
  private storage: MLSStorage;

  // In-memory cache of key packages
  private keyPackages: Map<string, StoredKeyPackageType> = new Map();

  constructor(config: ClientConfig) {
    this.identity = config.identity;
    this.credentialType = config.credentialType ?? CredentialType.BASIC;
    this.supportedCipherSuites = config.supportedCipherSuites ?? [
      CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
      CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
      CipherSuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    ];
    this.supportedVersions = config.supportedVersions ??
      [ProtocolVersion.MLS10];
    this.supportedExtensions = config.supportedExtensions ?? [];
    this.lifetimeInSeconds = config.lifetimeInSeconds ?? 86400 * 90; // 90 days default

    // Use provided storage or create appropriate default based on environment
    if (config.storage) {
      this.storage = config.storage;
    } else {
      // Use in-memory storage if IndexedDB is not available
      this.storage = typeof indexedDB !== "undefined"
        ? new MLSStorage()
        : new InMemoryMLSStorage();
    }
  }

  /**
   * Initialize the client and load stored key packages
   */
  async initialize(): Promise<void> {
    await this.storage.initialize();
    await this.loadStoredKeyPackages();
  }

  /**
   * Load key packages from storage
   */
  private async loadStoredKeyPackages(): Promise<void> {
    const clientId = this.getClientId();
    const storedPackages = await this.storage.getAllKeyPackages(clientId);

    for (const stored of storedPackages) {
      const refKey = this.keyPackageRefToKey(stored.keyPackageRef);
      this.keyPackages.set(refKey, stored);
    }
  }

  /**
   * Get client ID derived from identity
   */
  private getClientId(): string {
    return btoa(String.fromCharCode(...this.identity));
  }

  /**
   * Convert KeyPackageRef to storage key
   */
  private keyPackageRefToKey(ref: KeyPackageRef): string {
    return btoa(String.fromCharCode(...ref));
  }

  /**
   * Generate a new KeyPackage for a specific cipher suite
   */
  async generateKeyPackage(cipherSuite: CipherSuite): Promise<KeyPackage> {
    // Ensure cipher suite is supported
    if (!this.supportedCipherSuites.includes(cipherSuite)) {
      throw new Error(`Cipher suite ${cipherSuite} not supported by client`);
    }

    // Generate key pairs
    const initKeyPair = generateHPKEKeyPair(cipherSuite);
    const encryptionKeyPair = generateHPKEKeyPair(cipherSuite);
    const signatureKeyPair = generateSignatureKeyPair(cipherSuite);

    // Create credential
    const credential: Credential = {
      credentialType: this.credentialType,
      identity: this.identity,
    };

    // Create capabilities
    const capabilities: Capabilities = {
      versions: this.supportedVersions,
      cipherSuites: this.supportedCipherSuites,
      extensions: this.supportedExtensions,
      proposals: [1, 2, 3], // ADD, UPDATE, REMOVE
      credentials: [this.credentialType],
    };

    // Create lifetime
    const now = Math.floor(Date.now() / 1000);
    const lifetime: Lifetime = {
      notBefore: BigInt(now),
      notAfter: BigInt(now + this.lifetimeInSeconds),
    };

    // Create leaf node
    const leafNode: LeafNode = {
      encryptionKey: encryptionKeyPair.publicKey,
      signatureKey: signatureKeyPair.publicKey,
      credential,
      capabilities,
      leafNodeSource: LeafNodeSource.KEY_PACKAGE,
      lifetime,
      extensions: [],
    };

    // Sign the leaf node
    const leafNodeTBS = encodeLeafNodeTBS(leafNode);
    leafNode.signature = signWithLabel(
      cipherSuite,
      signatureKeyPair.privateKey,
      "LeafNodeTBS",
      leafNodeTBS,
    );

    // Create KeyPackage
    const keyPackage: KeyPackage = {
      protocolVersion: ProtocolVersion.MLS10,
      cipherSuite,
      initKey: initKeyPair.publicKey,
      leafNode,
      extensions: [],
      signature: new Uint8Array(0), // Will be set after signing
    };

    // Sign the KeyPackage
    const keyPackageTBS = encodeKeyPackageTBS(keyPackage);
    keyPackage.signature = signWithLabel(
      cipherSuite,
      signatureKeyPair.privateKey,
      "KeyPackageTBS",
      keyPackageTBS,
    );

    // Calculate KeyPackage ref
    const keyPackageBytes = encodeKeyPackage(keyPackage);
    const keyPackageRef = hash(cipherSuite, keyPackageBytes);

    // Store the KeyPackage
    const stored: StoredKeyPackageType = {
      keyPackage,
      keyPackageRef,
      initPrivateKey: initKeyPair.privateKey,
      encryptionPrivateKey: encryptionKeyPair.privateKey,
      signaturePrivateKey: signatureKeyPair.privateKey,
      createdAt: now,
    };

    await this.storeKeyPackage(stored);

    return keyPackage;
  }

  /**
   * Store a KeyPackage
   */
  private async storeKeyPackage(stored: StoredKeyPackageType): Promise<void> {
    const clientId = this.getClientId();
    const refKey = this.keyPackageRefToKey(stored.keyPackageRef);

    // Store in memory cache
    this.keyPackages.set(refKey, stored);

    // Store in persistent storage
    await this.storage.storeKeyPackage(clientId, stored);
  }

  /**
   * Get a stored KeyPackage by reference
   */
  async getKeyPackage(
    keyPackageRef: KeyPackageRef,
  ): Promise<StoredKeyPackageType | null> {
    const refKey = this.keyPackageRefToKey(keyPackageRef);

    // Check memory cache first
    const cached = this.keyPackages.get(refKey);
    if (cached) {
      return cached;
    }

    // Check persistent storage
    const clientId = this.getClientId();
    const stored = await this.storage.getKeyPackage(clientId, keyPackageRef);

    if (stored) {
      // Add to cache
      this.keyPackages.set(refKey, stored);
    }

    return stored;
  }

  /**
   * Get all valid KeyPackages
   */
  getValidKeyPackages(): Promise<KeyPackage[]> {
    const now = Math.floor(Date.now() / 1000);
    const validPackages: KeyPackage[] = [];

    for (const stored of this.keyPackages.values()) {
      const lifetime = stored.keyPackage.leafNode.lifetime;
      if (
        lifetime &&
        BigInt(now) >= lifetime.notBefore &&
        BigInt(now) <= lifetime.notAfter
      ) {
        validPackages.push(stored.keyPackage);
      }
    }

    return Promise.resolve(validPackages);
  }

  /**
   * Delete a KeyPackage
   */
  async deleteKeyPackage(keyPackageRef: KeyPackageRef): Promise<void> {
    const clientId = this.getClientId();
    const refKey = this.keyPackageRefToKey(keyPackageRef);

    // Remove from cache
    this.keyPackages.delete(refKey);

    // Remove from storage
    await this.storage.deleteKeyPackage(clientId, keyPackageRef);
  }

  /**
   * Clean up expired KeyPackages
   */
  async cleanupExpiredKeyPackages(): Promise<number> {
    const now = Math.floor(Date.now() / 1000);
    const toDelete: KeyPackageRef[] = [];

    for (const stored of this.keyPackages.values()) {
      const lifetime = stored.keyPackage.leafNode.lifetime;
      if (lifetime && BigInt(now) > lifetime.notAfter) {
        toDelete.push(stored.keyPackageRef);
      }
    }

    for (const ref of toDelete) {
      await this.deleteKeyPackage(ref);
    }

    return toDelete.length;
  }

  /**
   * Generate multiple KeyPackages for different cipher suites
   */
  async generateKeyPackagesForAllSuites(): Promise<KeyPackage[]> {
    const packages: KeyPackage[] = [];

    for (const suite of this.supportedCipherSuites) {
      try {
        const keyPackage = await this.generateKeyPackage(suite);
        packages.push(keyPackage);
      } catch (error) {
        console.warn(
          `Failed to generate KeyPackage for suite ${suite}:`,
          error,
        );
      }
    }

    return packages;
  }

  /**
   * Get the client's identity
   */
  getIdentity(): Uint8Array {
    return this.identity;
  }

  /**
   * Get supported capabilities
   */
  getCapabilities(): Capabilities {
    return {
      versions: this.supportedVersions,
      cipherSuites: this.supportedCipherSuites,
      extensions: this.supportedExtensions,
      proposals: [1, 2, 3], // ADD, UPDATE, REMOVE
      credentials: [this.credentialType],
    };
  }

  /**
   * Update client configuration
   */
  updateConfiguration(config: Partial<ClientConfig>): void {
    if (config.identity) {
      this.identity = config.identity;
    }
    if (config.credentialType !== undefined) {
      this.credentialType = config.credentialType;
    }
    if (config.supportedCipherSuites) {
      this.supportedCipherSuites = config.supportedCipherSuites;
    }
    if (config.supportedVersions) {
      this.supportedVersions = config.supportedVersions;
    }
    if (config.supportedExtensions) {
      this.supportedExtensions = config.supportedExtensions;
    }
    if (config.lifetimeInSeconds !== undefined) {
      this.lifetimeInSeconds = config.lifetimeInSeconds;
    }
  }
}

/**
 * Create a basic MLS client with sensible defaults
 */
export async function createMLSClient(
  identity: string,
  storage?: MLSStorage,
): Promise<MLSClient> {
  const client = new MLSClient({
    identity: new TextEncoder().encode(identity),
    storage,
  });

  await client.initialize();
  return client;
}
