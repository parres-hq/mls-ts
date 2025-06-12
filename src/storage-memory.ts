/**
 * In-memory storage backend for MLS (for testing and non-browser environments)
 */

import type { Epoch, KeyPackageRef, LeafIndex } from "./types.ts";

import {
  MLSStorage,
  type StoredEpochSecrets,
  type StoredGroup,
  type StoredIdentity,
  type StoredKeyPackage,
} from "./storage.ts";

/**
 * In-memory implementation of MLSStorage
 */
export class InMemoryMLSStorage extends MLSStorage {
  private identities: Map<string, StoredIdentity> = new Map();
  private keyPackages: Map<string, Map<string, StoredKeyPackage>> = new Map();
  private groups: Map<string, StoredGroup> = new Map();
  private epochSecrets: Map<string, Map<string, StoredEpochSecrets>> =
    new Map();
  private messageKeys: Map<string, { key: Uint8Array; nonce: Uint8Array }> =
    new Map();
  private pendingProposals: Map<
    string,
    Array<{ proposal: Uint8Array; proposalRef: Uint8Array }>
  > = new Map();

  /**
   * Initialize the storage backend (no-op for in-memory)
   */
  override async initialize(): Promise<void> {
    // No-op for in-memory storage
  }

  /**
   * Close the database connection (no-op for in-memory)
   */
  override close(): void {
    // No-op for in-memory storage
  }

  // Identity operations

  override storeIdentity(identity: StoredIdentity): Promise<void> {
    this.identities.set(identity.id, identity);
    return Promise.resolve();
  }

  override getIdentity(id: string): Promise<StoredIdentity | null> {
    return Promise.resolve(this.identities.get(id) || null);
  }

  override deleteIdentity(id: string): Promise<void> {
    this.identities.delete(id);
    return Promise.resolve();
  }

  // KeyPackage operations

  override storeKeyPackage(
    clientId: string,
    keyPackage: StoredKeyPackage,
  ): Promise<void> {
    if (!this.keyPackages.has(clientId)) {
      this.keyPackages.set(clientId, new Map());
    }

    const refKey = this.arrayToKey(keyPackage.keyPackageRef);
    this.keyPackages.get(clientId)!.set(refKey, keyPackage);
    return Promise.resolve();
  }

  override getKeyPackage(
    clientId: string,
    keyPackageRef: KeyPackageRef,
  ): Promise<StoredKeyPackage | null> {
    const clientPackages = this.keyPackages.get(clientId);
    if (!clientPackages) return Promise.resolve(null);

    const refKey = this.arrayToKey(keyPackageRef);
    return Promise.resolve(clientPackages.get(refKey) || null);
  }

  override getAllKeyPackages(clientId: string): Promise<StoredKeyPackage[]> {
    const clientPackages = this.keyPackages.get(clientId);
    if (!clientPackages) return Promise.resolve([]);

    return Promise.resolve(Array.from(clientPackages.values()));
  }

  override deleteKeyPackage(
    clientId: string,
    keyPackageRef: KeyPackageRef,
  ): Promise<void> {
    const clientPackages = this.keyPackages.get(clientId);
    if (!clientPackages) return Promise.resolve();

    const refKey = this.arrayToKey(keyPackageRef);
    clientPackages.delete(refKey);
    return Promise.resolve();
  }

  override getOldestKeyPackage(): Promise<StoredKeyPackage | null> {
    let oldest: StoredKeyPackage | null = null;
    let oldestTime = Number.MAX_SAFE_INTEGER;

    for (const clientPackages of this.keyPackages.values()) {
      for (const pkg of clientPackages.values()) {
        if (pkg.createdAt < oldestTime) {
          oldest = pkg;
          oldestTime = pkg.createdAt;
        }
      }
    }

    return Promise.resolve(oldest);
  }

  // Group operations

  override storeGroup(group: StoredGroup): Promise<void> {
    this.groups.set(group.groupId, group);
    return Promise.resolve();
  }

  override getGroup(groupId: string): Promise<StoredGroup | null> {
    return Promise.resolve(this.groups.get(groupId) || null);
  }

  override deleteGroup(groupId: string): Promise<void> {
    this.groups.delete(groupId);

    // Delete related data
    this.epochSecrets.delete(groupId);

    // Delete message keys for this group
    for (const key of this.messageKeys.keys()) {
      if (key.startsWith(groupId + ":")) {
        this.messageKeys.delete(key);
      }
    }

    // Delete pending proposals
    this.pendingProposals.delete(groupId);
    return Promise.resolve();
  }

  override getAllGroups(): Promise<StoredGroup[]> {
    return Promise.resolve(Array.from(this.groups.values()));
  }

  // Epoch secrets operations

  override storeEpochSecrets(
    groupId: string,
    epoch: Epoch,
    secrets: StoredEpochSecrets,
  ): Promise<void> {
    if (!this.epochSecrets.has(groupId)) {
      this.epochSecrets.set(groupId, new Map());
    }

    this.epochSecrets.get(groupId)!.set(epoch.toString(), secrets);
    return Promise.resolve();
  }

  override getEpochSecrets(
    groupId: string,
    epoch: Epoch,
  ): Promise<StoredEpochSecrets | null> {
    const groupSecrets = this.epochSecrets.get(groupId);
    if (!groupSecrets) return Promise.resolve(null);

    return Promise.resolve(groupSecrets.get(epoch.toString()) || null);
  }

  override deleteOldEpochSecrets(
    groupId: string,
    currentEpoch: Epoch,
  ): Promise<void> {
    const groupSecrets = this.epochSecrets.get(groupId);
    if (!groupSecrets) return Promise.resolve();

    for (const [epochStr] of groupSecrets) {
      if (BigInt(epochStr) < currentEpoch) {
        groupSecrets.delete(epochStr);
      }
    }
    return Promise.resolve();
  }

  // Message key operations

  override storeMessageKey(
    groupId: string,
    epoch: Epoch,
    sender: LeafIndex,
    generation: number,
    key: Uint8Array,
    nonce: Uint8Array,
  ): Promise<void> {
    const keyStr = `${groupId}:${epoch}:${sender}:${generation}`;
    this.messageKeys.set(keyStr, { key, nonce });
    return Promise.resolve();
  }

  override getMessageKey(
    groupId: string,
    epoch: Epoch,
    sender: LeafIndex,
    generation: number,
  ): Promise<{ key: Uint8Array; nonce: Uint8Array } | null> {
    const keyStr = `${groupId}:${epoch}:${sender}:${generation}`;
    return Promise.resolve(this.messageKeys.get(keyStr) || null);
  }

  override deleteMessageKey(
    groupId: string,
    epoch: Epoch,
    sender: LeafIndex,
    generation: number,
  ): Promise<void> {
    const keyStr = `${groupId}:${epoch}:${sender}:${generation}`;
    this.messageKeys.delete(keyStr);
    return Promise.resolve();
  }

  // Pending proposal operations

  override storePendingProposal(
    groupId: string,
    proposal: Uint8Array,
    proposalRef: Uint8Array,
  ): Promise<void> {
    if (!this.pendingProposals.has(groupId)) {
      this.pendingProposals.set(groupId, []);
    }

    this.pendingProposals.get(groupId)!.push({ proposal, proposalRef });
    return Promise.resolve();
  }

  override getPendingProposals(groupId: string): Promise<
    Array<{
      proposal: Uint8Array;
      proposalRef: Uint8Array;
    }>
  > {
    return Promise.resolve(this.pendingProposals.get(groupId) || []);
  }

  override clearPendingProposals(groupId: string): Promise<void> {
    this.pendingProposals.delete(groupId);
    return Promise.resolve();
  }

  /**
   * Clear all data
   */
  override clearAll(): Promise<void> {
    this.identities.clear();
    this.keyPackages.clear();
    this.groups.clear();
    this.epochSecrets.clear();
    this.messageKeys.clear();
    this.pendingProposals.clear();
    return Promise.resolve();
  }

  /**
   * Export all data (for backup)
   */
  override exportAll(): Promise<{
    identities: StoredIdentity[];
    keyPackages: StoredKeyPackage[];
    groups: StoredGroup[];
  }> {
    const keyPackages: StoredKeyPackage[] = [];
    for (const [clientId, packages] of this.keyPackages) {
      for (const pkg of packages.values()) {
        keyPackages.push(pkg); // Remove the clientId spread since it's not part of StoredKeyPackage
      }
    }

    return Promise.resolve({
      identities: Array.from(this.identities.values()),
      keyPackages,
      groups: Array.from(this.groups.values()),
    });
  }

  // Helper to convert Uint8Array to string key
  private arrayToKey(arr: Uint8Array): string {
    return btoa(String.fromCharCode(...arr));
  }
}

/**
 * Create appropriate storage based on environment
 */
export async function createStorage(
  clientId: string = "default",
): Promise<MLSStorage> {
  // Check if we're in a browser environment with IndexedDB
  if (typeof indexedDB !== "undefined") {
    const { MLSStorage } = await import("./storage.ts");
    const storage = new MLSStorage(clientId);
    await storage.initialize();
    return storage;
  } else {
    // Use in-memory storage for non-browser environments
    const storage = new InMemoryMLSStorage(clientId);
    await storage.initialize();
    return storage;
  }
}
