/**
 * IndexedDB storage backend for MLS
 */

import type {
  Epoch,
  GroupContext,
  GroupID,
  HPKEPrivateKey,
  KeyPackage,
  KeyPackageRef,
  LeafIndex,
  RatchetNode,
  SignaturePrivateKey,
} from "./types.ts";

export interface StoredKeyPackage {
  keyPackage: KeyPackage;
  keyPackageRef: KeyPackageRef;
  initPrivateKey: HPKEPrivateKey;
  encryptionPrivateKey: HPKEPrivateKey;
  signaturePrivateKey: SignaturePrivateKey;
  createdAt: number;
}

export interface StoredGroup {
  groupId: string; // base64 encoded
  epoch: string; // bigint as string
  groupContext: GroupContext;
  myLeafIndex: LeafIndex;
  epochSecrets: StoredEpochSecrets;
  ratchetTree: StoredRatchetTree;
  lastUpdate: number;
}

export interface StoredEpochSecrets {
  initSecret: Uint8Array;
  commitSecret: Uint8Array;
  epochSecret: Uint8Array;
  confirmationKey: Uint8Array;
  membershipKey: Uint8Array;
  resumptionPsk: Uint8Array;
  epochAuthenticator: Uint8Array;
  externalSecret: Uint8Array;
  senderDataSecret: Uint8Array;
  encryptionSecret: Uint8Array;
  exporterSecret: Uint8Array;
}

export interface StoredRatchetTree {
  nodes: (RatchetNode | null)[];
  privateKeys: Map<number, HPKEPrivateKey>; // node index -> private key
}

export interface StoredIdentity {
  id: string;
  signaturePrivateKey: SignaturePrivateKey;
  credential: Uint8Array; // serialized credential
  createdAt: number;
}

const DB_NAME = "mls-storage";
const DB_VERSION = 1;

// Object store names
const STORES = {
  IDENTITIES: "identities",
  KEY_PACKAGES: "keyPackages",
  GROUPS: "groups",
  EPOCH_SECRETS: "epochSecrets",
  MESSAGE_KEYS: "messageKeys",
  PENDING_PROPOSALS: "pendingProposals",
} as const;

export class MLSStorage {
  private db: IDBDatabase | null = null;
  private readonly dbName: string;

  constructor(clientId = "default") {
    this.dbName = `${DB_NAME}-${clientId}`;
  }

  /**
   * Initialize the storage backend
   */
  initialize(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, DB_VERSION);

      request.onerror = () => reject(new Error("Failed to open IndexedDB"));

      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Create object stores if they don't exist
        if (!db.objectStoreNames.contains(STORES.IDENTITIES)) {
          db.createObjectStore(STORES.IDENTITIES, { keyPath: "id" });
        }

        if (!db.objectStoreNames.contains(STORES.KEY_PACKAGES)) {
          const store = db.createObjectStore(STORES.KEY_PACKAGES, {
            autoIncrement: true,
          });
          store.createIndex("clientId", "clientId", { unique: false });
          store.createIndex("keyPackageRef", "keyPackageRef", { unique: true });
          store.createIndex("createdAt", "createdAt", { unique: false });
        }

        if (!db.objectStoreNames.contains(STORES.GROUPS)) {
          const store = db.createObjectStore(STORES.GROUPS, {
            keyPath: "groupId",
          });
          store.createIndex("lastUpdate", "lastUpdate", { unique: false });
        }

        if (!db.objectStoreNames.contains(STORES.EPOCH_SECRETS)) {
          const store = db.createObjectStore(STORES.EPOCH_SECRETS, {
            keyPath: ["groupId", "epoch"],
          });
          store.createIndex("groupId", "groupId", { unique: false });
        }

        if (!db.objectStoreNames.contains(STORES.MESSAGE_KEYS)) {
          const store = db.createObjectStore(STORES.MESSAGE_KEYS, {
            keyPath: ["groupId", "epoch", "sender", "generation"],
          });
          store.createIndex("groupId", "groupId", { unique: false });
        }

        if (!db.objectStoreNames.contains(STORES.PENDING_PROPOSALS)) {
          const store = db.createObjectStore(STORES.PENDING_PROPOSALS, {
            autoIncrement: true,
          });
          store.createIndex("groupId", "groupId", { unique: false });
        }
      };
    });
  }

  /**
   * Close the database connection
   */
  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  /**
   * Ensure database is open
   */
  private ensureOpen(): IDBDatabase {
    if (!this.db) {
      throw new Error("Database not initialized. Call init() first.");
    }
    return this.db;
  }

  /**
   * Helper to promisify IDB requests
   */
  private promisifyRequest<T>(request: IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  // Identity operations

  async storeIdentity(identity: StoredIdentity): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.IDENTITIES], "readwrite");
    const store = tx.objectStore(STORES.IDENTITIES);
    await this.promisifyRequest(store.put(identity));
  }

  async getIdentity(id: string): Promise<StoredIdentity | null> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.IDENTITIES], "readonly");
    const store = tx.objectStore(STORES.IDENTITIES);
    const result = await this.promisifyRequest(store.get(id));
    return result || null;
  }

  async deleteIdentity(id: string): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.IDENTITIES], "readwrite");
    const store = tx.objectStore(STORES.IDENTITIES);
    await this.promisifyRequest(store.delete(id));
  }

  // KeyPackage operations

  async storeKeyPackage(
    clientId: string,
    keyPackage: StoredKeyPackage,
  ): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.KEY_PACKAGES], "readwrite");
    const store = tx.objectStore(STORES.KEY_PACKAGES);
    await this.promisifyRequest(store.put({
      ...keyPackage,
      clientId,
      keyPackageRef: Array.from(keyPackage.keyPackageRef), // Convert to array for storage
    }));
  }

  async getKeyPackage(
    clientId: string,
    keyPackageRef: KeyPackageRef,
  ): Promise<StoredKeyPackage | null> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.KEY_PACKAGES], "readonly");
    const store = tx.objectStore(STORES.KEY_PACKAGES);
    const index = store.index("keyPackageRef");
    const refArray = Array.from(keyPackageRef);
    const result = await this.promisifyRequest(index.get(refArray));

    if (!result || result.clientId !== clientId) {
      return null;
    }

    // Convert array back to Uint8Array
    return {
      ...result,
      keyPackageRef: new Uint8Array(result.keyPackageRef),
    };
  }

  async getAllKeyPackages(clientId: string): Promise<StoredKeyPackage[]> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.KEY_PACKAGES], "readonly");
    const store = tx.objectStore(STORES.KEY_PACKAGES);
    const index = store.index("clientId");
    const results = await this.promisifyRequest(index.getAll(clientId));

    // Convert arrays back to Uint8Arrays
    return results.map((r) => ({
      ...r,
      keyPackageRef: new Uint8Array(r.keyPackageRef),
    }));
  }

  async deleteKeyPackage(
    clientId: string,
    keyPackageRef: KeyPackageRef,
  ): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.KEY_PACKAGES], "readonly");
    const store = tx.objectStore(STORES.KEY_PACKAGES);
    const index = store.index("keyPackageRef");
    const refArray = Array.from(keyPackageRef);
    const cursor = await this.promisifyRequest(index.openCursor(refArray));

    if (cursor && cursor.value.clientId === clientId) {
      const deleteTx = db.transaction([STORES.KEY_PACKAGES], "readwrite");
      const deleteStore = deleteTx.objectStore(STORES.KEY_PACKAGES);
      await this.promisifyRequest(deleteStore.delete(cursor.primaryKey));
    }
  }

  async getOldestKeyPackage(): Promise<StoredKeyPackage | null> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.KEY_PACKAGES], "readonly");
    const store = tx.objectStore(STORES.KEY_PACKAGES);
    const index = store.index("createdAt");
    const cursor = await this.promisifyRequest(index.openCursor());

    if (!cursor) return null;

    // Convert array back to Uint8Array
    return {
      ...cursor.value,
      keyPackageRef: new Uint8Array(cursor.value.keyPackageRef),
    };
  }

  // Group operations

  async storeGroup(group: StoredGroup): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.GROUPS], "readwrite");
    const store = tx.objectStore(STORES.GROUPS);
    await this.promisifyRequest(store.put(group));
  }

  async getGroup(groupId: string): Promise<StoredGroup | null> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.GROUPS], "readonly");
    const store = tx.objectStore(STORES.GROUPS);
    const result = await this.promisifyRequest(store.get(groupId));
    return result || null;
  }

  async deleteGroup(groupId: string): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction([
      STORES.GROUPS,
      STORES.EPOCH_SECRETS,
      STORES.MESSAGE_KEYS,
      STORES.PENDING_PROPOSALS,
    ], "readwrite");

    // Delete the group
    const groupStore = tx.objectStore(STORES.GROUPS);
    await this.promisifyRequest(groupStore.delete(groupId));

    // Delete all epoch secrets for this group
    const epochStore = tx.objectStore(STORES.EPOCH_SECRETS);
    const epochIndex = epochStore.index("groupId");
    const epochCursor = await this.promisifyRequest(
      epochIndex.openCursor(groupId),
    );
    if (epochCursor) {
      await this.deleteAllInCursor(epochCursor);
    }

    // Delete all message keys for this group
    const keyStore = tx.objectStore(STORES.MESSAGE_KEYS);
    const keyIndex = keyStore.index("groupId");
    const keyCursor = await this.promisifyRequest(keyIndex.openCursor(groupId));
    if (keyCursor) {
      await this.deleteAllInCursor(keyCursor);
    }

    // Delete all pending proposals for this group
    const proposalStore = tx.objectStore(STORES.PENDING_PROPOSALS);
    const proposalIndex = proposalStore.index("groupId");
    const proposalCursor = await this.promisifyRequest(
      proposalIndex.openCursor(groupId),
    );
    if (proposalCursor) {
      await this.deleteAllInCursor(proposalCursor);
    }
  }

  async getAllGroups(): Promise<StoredGroup[]> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.GROUPS], "readonly");
    const store = tx.objectStore(STORES.GROUPS);
    return await this.promisifyRequest(store.getAll());
  }

  // Epoch secrets operations

  async storeEpochSecrets(
    groupId: string,
    epoch: Epoch,
    secrets: StoredEpochSecrets,
  ): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.EPOCH_SECRETS], "readwrite");
    const store = tx.objectStore(STORES.EPOCH_SECRETS);
    await this.promisifyRequest(store.put({
      groupId,
      epoch: epoch.toString(),
      secrets,
      timestamp: Date.now(),
    }));
  }

  async getEpochSecrets(
    groupId: string,
    epoch: Epoch,
  ): Promise<StoredEpochSecrets | null> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.EPOCH_SECRETS], "readonly");
    const store = tx.objectStore(STORES.EPOCH_SECRETS);
    const result = await this.promisifyRequest(
      store.get([groupId, epoch.toString()]),
    );
    return result?.secrets || null;
  }

  async deleteOldEpochSecrets(
    groupId: string,
    currentEpoch: Epoch,
  ): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.EPOCH_SECRETS], "readwrite");
    const store = tx.objectStore(STORES.EPOCH_SECRETS);
    const index = store.index("groupId");
    const cursor = await this.promisifyRequest(index.openCursor(groupId));

    if (cursor) {
      do {
        const epochBigInt = BigInt(cursor.value.epoch);
        if (epochBigInt < currentEpoch) {
          await this.promisifyRequest(cursor.delete());
        }
        // cursor.continue() returns void, just call it directly
        cursor.continue();
        // Wait a bit to let the cursor advance
        await new Promise((resolve) => setTimeout(resolve, 0));
      } while (cursor.key);
    }
  }

  // Message key operations

  async storeMessageKey(
    groupId: string,
    epoch: Epoch,
    sender: LeafIndex,
    generation: number,
    key: Uint8Array,
    nonce: Uint8Array,
  ): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.MESSAGE_KEYS], "readwrite");
    const store = tx.objectStore(STORES.MESSAGE_KEYS);
    await this.promisifyRequest(store.put({
      groupId,
      epoch: epoch.toString(),
      sender,
      generation,
      key,
      nonce,
      timestamp: Date.now(),
    }));
  }

  async getMessageKey(
    groupId: string,
    epoch: Epoch,
    sender: LeafIndex,
    generation: number,
  ): Promise<{ key: Uint8Array; nonce: Uint8Array } | null> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.MESSAGE_KEYS], "readonly");
    const store = tx.objectStore(STORES.MESSAGE_KEYS);
    const result = await this.promisifyRequest(
      store.get([groupId, epoch.toString(), sender, generation]),
    );
    return result ? { key: result.key, nonce: result.nonce } : null;
  }

  async deleteMessageKey(
    groupId: string,
    epoch: Epoch,
    sender: LeafIndex,
    generation: number,
  ): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.MESSAGE_KEYS], "readwrite");
    const store = tx.objectStore(STORES.MESSAGE_KEYS);
    await this.promisifyRequest(
      store.delete([groupId, epoch.toString(), sender, generation]),
    );
  }

  // Pending proposal operations

  async storePendingProposal(
    groupId: string,
    proposal: Uint8Array,
    proposalRef: Uint8Array,
  ): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.PENDING_PROPOSALS], "readwrite");
    const store = tx.objectStore(STORES.PENDING_PROPOSALS);
    await this.promisifyRequest(store.add({
      groupId,
      proposal,
      proposalRef,
      timestamp: Date.now(),
    }));
  }

  async getPendingProposals(groupId: string): Promise<
    Array<{
      proposal: Uint8Array;
      proposalRef: Uint8Array;
    }>
  > {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.PENDING_PROPOSALS], "readonly");
    const store = tx.objectStore(STORES.PENDING_PROPOSALS);
    const index = store.index("groupId");
    const results = await this.promisifyRequest(index.getAll(groupId));
    return results.map((r) => ({
      proposal: r.proposal,
      proposalRef: r.proposalRef,
    }));
  }

  async clearPendingProposals(groupId: string): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.PENDING_PROPOSALS], "readwrite");
    const store = tx.objectStore(STORES.PENDING_PROPOSALS);
    const index = store.index("groupId");
    const cursor = await this.promisifyRequest(index.openCursor(groupId));

    if (cursor) {
      await this.deleteAllInCursor(cursor);
    }
  }

  // Helper methods

  private async deleteAllInCursor(cursor: IDBCursorWithValue): Promise<void> {
    do {
      await this.promisifyRequest(cursor.delete());
      // cursor.continue() returns void, just call it directly
      cursor.continue();
      // Wait a bit to let the cursor advance
      await new Promise((resolve) => setTimeout(resolve, 0));
    } while (cursor.key);
  }

  /**
   * Clear all data (use with caution!)
   */
  async clearAll(): Promise<void> {
    const db = this.ensureOpen();
    const tx = db.transaction(
      [
        STORES.IDENTITIES,
        STORES.KEY_PACKAGES,
        STORES.GROUPS,
        STORES.EPOCH_SECRETS,
        STORES.MESSAGE_KEYS,
        STORES.PENDING_PROPOSALS,
      ],
      "readwrite",
    );

    for (const storeName of Object.values(STORES)) {
      const store = tx.objectStore(storeName);
      await this.promisifyRequest(store.clear());
    }
  }

  /**
   * Export all data (for backup)
   */
  async exportAll(): Promise<{
    identities: StoredIdentity[];
    keyPackages: StoredKeyPackage[];
    groups: StoredGroup[];
  }> {
    const identities = await this.getAllIdentities();
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.KEY_PACKAGES], "readonly");
    const store = tx.objectStore(STORES.KEY_PACKAGES);
    const keyPackages = await this.promisifyRequest(store.getAll());
    const groups = await this.getAllGroups();

    return { identities, keyPackages, groups };
  }

  private async getAllIdentities(): Promise<StoredIdentity[]> {
    const db = this.ensureOpen();
    const tx = db.transaction([STORES.IDENTITIES], "readonly");
    const store = tx.objectStore(STORES.IDENTITIES);
    return await this.promisifyRequest(store.getAll());
  }
}

// Helper function to create storage instance
export async function createStorage(
  clientId = "default",
): Promise<MLSStorage> {
  const storage = new MLSStorage(clientId);
  await storage.initialize();
  return storage;
}

// Helper to encode/decode group IDs for storage
export function encodeGroupId(groupId: GroupID): string {
  return btoa(String.fromCharCode(...groupId));
}

export function decodeGroupId(encoded: string): GroupID {
  return new Uint8Array(atob(encoded).split("").map((c) => c.charCodeAt(0)));
}
