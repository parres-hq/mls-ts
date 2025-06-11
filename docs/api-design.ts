/**
 * MLS Client and Group API Design
 * This file serves as the blueprint for the high-level API
 */

// ============================================================================
// Client API
// ============================================================================

interface MLSClientConfig {
  identity: ClientIdentity;
  storage?: MLSStorage;
  cipherSuites?: CipherSuite[];
  credentialType?: CredentialType;
}

interface ClientIdentity {
  identifier: string;
  displayName?: string;
  credential?: Uint8Array; // For X.509 or custom credentials
}

class MLSClient {
  /**
   * Create a new MLS client
   */
  static async create(config: MLSClientConfig): Promise<MLSClient>;

  /**
   * Generate a new KeyPackage
   */
  async createKeyPackage(
    cipherSuite: CipherSuite,
    lifetime?: Lifetime
  ): Promise<KeyPackage>;

  /**
   * Create a new group
   */
  async createGroup(
    groupId: Uint8Array,
    cipherSuite: CipherSuite,
    extensions?: Extension[]
  ): Promise<MLSGroup>;

  /**
   * Join a group from a Welcome message
   */
  async joinGroup(welcome: Welcome): Promise<MLSGroup>;

  /**
   * Get all active groups
   */
  async getGroups(): Promise<MLSGroup[]>;

  /**
   * Export client state for backup
   */
  async exportState(): Promise<ClientBackup>;

  /**
   * Import client state from backup
   */
  static async importState(backup: ClientBackup): Promise<MLSClient>;
}

// ============================================================================
// Group API
// ============================================================================

interface MLSGroup extends EventEmitter {
  // Properties
  readonly groupId: Uint8Array;
  readonly epoch: bigint;
  readonly cipherSuite: CipherSuite;
  readonly members: GroupMember[];
  readonly myLeafIndex: LeafIndex;

  // Proposals
  /**
   * Propose adding a new member
   */
  async proposeAdd(keyPackage: KeyPackage): Promise<ProposalRef>;

  /**
   * Propose removing a member
   */
  async proposeRemove(member: GroupMember): Promise<ProposalRef>;

  /**
   * Propose updating own key material
   */
  async proposeUpdate(
    leafNode?: Partial<LeafNodeOptions>
  ): Promise<ProposalRef>;

  /**
   * Propose a PSK
   */
  async proposePSK(psk: PreSharedKeyID): Promise<ProposalRef>;

  // Commits
  /**
   * Commit pending proposals
   */
  async commit(
    additionalProposals?: ProposalRef[]
  ): Promise<{
    commit: MLSMessage;
    welcome?: Welcome;
  }>;

  /**
   * Process received message (Proposal or Commit)
   */
  async processMessage(message: MLSMessage): Promise<void>;

  // Messaging
  /**
   * Encrypt an application message
   */
  async encrypt(
    plaintext: Uint8Array,
    authenticatedData?: Uint8Array
  ): Promise<MLSMessage>;

  /**
   * Decrypt an application message
   */
  async decrypt(message: MLSMessage): Promise<{
    plaintext: Uint8Array;
    sender: GroupMember;
    authenticatedData: Uint8Array;
  }>;

  // State Management
  /**
   * Export group state for backup
   */
  async exportState(): Promise<GroupBackup>;

  /**
   * Get group info for external joins
   */
  async getGroupInfo(): Promise<GroupInfo>;

  /**
   * Get pending proposals
   */
  getPendingProposals(): Proposal[];

  // Events
  on(event: 'member-added', listener: (member: GroupMember) => void): this;
  on(event: 'member-removed', listener: (member: GroupMember) => void): this;
  on(event: 'member-updated', listener: (member: GroupMember) => void): this;
  on(event: 'epoch-changed', listener: (epoch: bigint) => void): this;
  on(event: 'proposal-received', listener: (proposal: Proposal) => void): this;
}

// ============================================================================
// Supporting Types
// ============================================================================

interface GroupMember {
  leafIndex: LeafIndex;
  identity: ClientIdentity;
  credential: Credential;
  addedInEpoch: bigint;
  lastUpdatedEpoch: bigint;
  publicKey: {
    signature: Uint8Array;
    encryption: Uint8Array;
  };
}

interface LeafNodeOptions {
  encryptionKey?: HPKEKeyPair;
  signatureKey?: SignatureKeyPair;
  extensions?: Extension[];
  capabilities?: Capabilities;
}

interface ClientBackup {
  version: string;
  identity: ClientIdentity;
  keyPackages: SerializedKeyPackage[];
  groups: GroupBackup[];
  timestamp: number;
}

interface GroupBackup {
  version: string;
  groupId: Uint8Array;
  epoch: bigint;
  cipherSuite: CipherSuite;
  tree: SerializedTree;
  keyScheduleState: Uint8Array;
  pendingProposals: Proposal[];
}

// ============================================================================
// Error Types
// ============================================================================

class MLSError extends Error {
  constructor(message: string, public code: MLSErrorCode) {
    super(message);
  }
}

enum MLSErrorCode {
  // Crypto errors
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  
  // Protocol errors
  WRONG_EPOCH = 'WRONG_EPOCH',
  INVALID_PROPOSAL = 'INVALID_PROPOSAL',
  INVALID_COMMIT = 'INVALID_COMMIT',
  
  // State errors
  NOT_MEMBER = 'NOT_MEMBER',
  ALREADY_MEMBER = 'ALREADY_MEMBER',
  GROUP_NOT_FOUND = 'GROUP_NOT_FOUND',
  
  // Validation errors
  EXPIRED_CREDENTIAL = 'EXPIRED_CREDENTIAL',
  UNSUPPORTED_VERSION = 'UNSUPPORTED_VERSION',
  CAPABILITIES_MISMATCH = 'CAPABILITIES_MISMATCH',
}

// ============================================================================
// Usage Examples
// ============================================================================

/*
// Create clients
const alice = await MLSClient.create({
  identity: { identifier: 'alice@example.com' }
});

const bob = await MLSClient.create({
  identity: { identifier: 'bob@example.com' }
});

// Bob publishes a KeyPackage
const bobKP = await bob.createKeyPackage(
  CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
);

// Alice creates a group and adds Bob
const group = await alice.createGroup(
  crypto.getRandomValues(new Uint8Array(32)),
  CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
);

const addProposal = await group.proposeAdd(bobKP);
const { commit, welcome } = await group.commit();

// Bob joins the group
const bobGroup = await bob.joinGroup(welcome);

// Send messages
const message = await group.encrypt(
  new TextEncoder().encode('Hello Bob!')
);

const { plaintext, sender } = await bobGroup.decrypt(message);
console.log(`${sender.identity.identifier}: ${new TextDecoder().decode(plaintext)}`);

// Handle events
group.on('member-added', (member) => {
  console.log(`${member.identity.identifier} joined the group`);
});

group.on('epoch-changed', (epoch) => {
  console.log(`Epoch changed to ${epoch}`);
});
*/