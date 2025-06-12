/**
 * Core types and constants for MLS protocol
 * Based on RFC 9420
 */

// Protocol version
export const MLS_VERSION = 0x0001; // mls10

// Protocol version enum for convenience
export enum ProtocolVersion {
  MLS10 = 0x0001,
}

// Cipher Suites (from Section 17.1)
export enum CipherSuite {
  MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
  MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
  MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
  MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
  MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
  MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
  MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,
}

// Content types
export enum ContentType {
  RESERVED = 0,
  APPLICATION = 1,
  PROPOSAL = 2,
  COMMIT = 3,
}

// Sender types
export enum SenderType {
  RESERVED = 0,
  MEMBER = 1,
  EXTERNAL = 2,
  NEW_MEMBER_PROPOSAL = 3,
  NEW_MEMBER_COMMIT = 4,
}

// Wire formats
export enum WireFormat {
  Reserved = 0,
  PublicMessage = 1,
  PrivateMessage = 2,
  Welcome = 3,
  GroupInfo = 4,
  KeyPackage = 5,
}

// Proposal types
export enum ProposalType {
  INVALID = 0,
  ADD = 1,
  UPDATE = 2,
  REMOVE = 3,
  PSK = 4,
  REINIT = 5,
  EXTERNAL_INIT = 6,
  GROUP_CONTEXT_EXTENSIONS = 7,
}

// Credential types
export enum CredentialType {
  RESERVED = 0,
  BASIC = 1,
  X509 = 2,
}

// Extension types
export enum ExtensionType {
  INVALID = 0,
  APPLICATION_ID = 1,
  RATCHET_TREE = 2,
  REQUIRED_CAPABILITIES = 3,
  EXTERNAL_PUB = 4,
  EXTERNAL_SENDERS = 5,
}

// Leaf node sources
export enum LeafNodeSource {
  RESERVED = 0,
  KEY_PACKAGE = 1,
  UPDATE = 2,
  COMMIT = 3,
}

// PSK types
export enum PSKType {
  RESERVED = 0,
  EXTERNAL = 1,
  RESUMPTION = 2,
}

// Resumption PSK usage
export enum ResumptionPSKUsage {
  RESERVED = 0,
  APPLICATION = 1,
  REINIT = 2,
  BRANCH = 3,
}

// Basic types
export type GroupID = Uint8Array;
export type Epoch = bigint;
export type NodeIndex = number;
export type LeafIndex = number;

// Opaque byte arrays
export type HPKEPublicKey = Uint8Array;
export type HPKEPrivateKey = Uint8Array;
export type SignaturePublicKey = Uint8Array;
export type SignaturePrivateKey = Uint8Array;
export type KeyPackageRef = Uint8Array;
export type ProposalRef = Uint8Array;
export type Secret = Uint8Array;

// Sender structure
export interface Sender {
  senderType: SenderType;
  leafIndex?: LeafIndex;
  senderIndex?: number;
}

// Credential structure
export interface Credential {
  credentialType: CredentialType;
  identity?: Uint8Array; // For basic credentials
  certificates?: Uint8Array[]; // For X509 credentials
}

export interface X509Credential {
  certificates: Uint8Array[];
}

// Capabilities structure
export interface Capabilities {
  versions: ProtocolVersion[];
  cipherSuites: CipherSuite[];
  extensions: ExtensionType[];
  proposals: ProposalType[];
  credentials: CredentialType[];
}

// Extension structure
export interface Extension {
  extensionType: ExtensionType;
  extensionData: Uint8Array;
}

// Lifetime structure
export interface Lifetime {
  notBefore: bigint;
  notAfter: bigint;
}

// LeafNode structure
export interface LeafNode {
  encryptionKey: HPKEPublicKey;
  signatureKey: SignaturePublicKey;
  credential: Credential;
  capabilities: Capabilities;
  leafNodeSource: LeafNodeSource;
  lifetime?: Lifetime;
  parentHash?: Uint8Array;
  extensions: Extension[];
  signature?: Uint8Array; // Added signature field
}

// ParentNode structure
export interface ParentNode {
  encryptionKey: HPKEPublicKey;
  parentHash: Uint8Array;
  unmergedLeaves: LeafIndex[];
}

// KeyPackage structure
export interface KeyPackage {
  protocolVersion: ProtocolVersion;
  cipherSuite: CipherSuite;
  initKey: HPKEPublicKey;
  leafNode: LeafNode;
  extensions: Extension[];
  signature: Uint8Array;
}

// GroupContext structure
export interface GroupContext {
  protocolVersion: ProtocolVersion;
  cipherSuite: CipherSuite;
  groupId: GroupID;
  epoch: Epoch;
  treeHash: Uint8Array;
  confirmedTranscriptHash: Uint8Array;
  extensions: Extension[];
}

// Node in the ratchet tree
export type RatchetNode = LeafNode | ParentNode | null;

// Tree node type discriminator
export enum NodeType {
  LEAF = 1,
  PARENT = 2,
}

// HPKECiphertext structure
export interface HPKECiphertext {
  kemOutput: Uint8Array;
  ciphertext: Uint8Array;
}

// UpdatePathNode structure
export interface UpdatePathNode {
  encryptionKey: HPKEPublicKey; // Changed back to encryptionKey for consistency
  encryptedPathSecrets: Uint8Array[]; // Simplified from HPKECiphertext[]
}

// UpdatePath structure
export interface UpdatePath {
  leafNode: LeafNode;
  nodes: UpdatePathNode[];
}

// FramedContent structure
export interface FramedContent {
  groupId: GroupID;
  epoch: Epoch;
  sender: Sender;
  authenticatedData: Uint8Array;
  contentType: ContentType;
  // Direct fields instead of union
  applicationData?: Uint8Array;
  proposal?: Proposal;
  commit?: Commit;
}

// ApplicationData structure
export interface ApplicationData {
  data: Uint8Array;
}

// FramedContentAuthData structure
export interface FramedContentAuthData {
  signature: Uint8Array;
  confirmationTag?: Uint8Array; // only for commit
}

// AuthenticatedContent structure
export interface AuthenticatedContent {
  wireFormat: WireFormat;
  content: FramedContent;
  auth: FramedContentAuthData;
}

// Proposal types
export interface Add {
  keyPackage: KeyPackage;
}

export interface Update {
  leafNode: LeafNode;
}

export interface Remove {
  removed: LeafIndex;
}

export interface PreSharedKey {
  psk: PreSharedKeyID;
}

// ReInit structure
export interface ReInit {
  groupId: GroupID;
  protocolVersion: ProtocolVersion;
  cipherSuite: CipherSuite;
  extensions: Extension[];
}

export interface ExternalInit {
  kemOutput: Uint8Array;
}

export interface GroupContextExtensions {
  groupContextExtensions: Extension[];
}

// Proposal structure - simplified to use direct fields
export interface Proposal {
  proposalType: ProposalType;
  add?: Add;
  update?: Update;
  remove?: Remove;
  psk?: PreSharedKey;
  reinit?: ReInit;
  externalInit?: ExternalInit;
  groupContextExtensions?: GroupContextExtensions;
}

// ProposalOrRef type
export type ProposalOrRef =
  | { type: "proposal"; proposal: Proposal }
  | { type: "reference"; reference: ProposalRef };

// Commit structure
export interface Commit {
  proposals: ProposalRef[];
  path?: UpdatePath; // Changed from updatePath to path
}

// PreSharedKeyID structure
export interface PreSharedKeyID {
  pskType: PSKType;
  pskId?: Uint8Array; // for external
  usage?: ResumptionPSKUsage; // for resumption
  pskGroupId?: GroupID; // for resumption
  pskEpoch?: Epoch; // for resumption
  pskNonce: Uint8Array;
}

// Welcome-related structures
export interface GroupSecrets {
  joinerSecret: Secret;
  pathSecret?: Secret;
  psks: PreSharedKeyID[]; // Changed from optional to required array
}

export interface GroupInfo {
  groupContext: GroupContext;
  extensions: Extension[];
  confirmationTag: Uint8Array;
  signerIndex: LeafIndex;
  signature: Uint8Array;
}

export interface EncryptedGroupSecrets {
  keyPackageRef: KeyPackageRef;
  kemOutput: Uint8Array; // KEM output for HPKE
  encryptedGroupSecrets: Uint8Array; // Actual encrypted content
}

export interface Welcome {
  cipherSuite: CipherSuite;
  secrets: EncryptedGroupSecrets[];
  encryptedGroupInfo: Uint8Array;
}

// PublicMessage structure
export interface PublicMessage {
  content: FramedContent;
  authTag: Uint8Array;
  membershipTag?: Uint8Array;
}

// PrivateMessage structure
export interface PrivateMessage {
  groupId: GroupID;
  epoch: Epoch;
  contentType: ContentType;
  authenticatedData: Uint8Array;
  encryptedSenderData: Uint8Array;
  generation: bigint;
}

// MLSMessage structure
export interface MLSMessage {
  protocolVersion: ProtocolVersion;
  wireFormat: WireFormat;
  message: PublicMessage | PrivateMessage | Welcome | GroupInfo | KeyPackage;
}

// Additional type exports
export interface GroupInfoTBS {
  groupContext: GroupContext;
  extensions: Extension[];
  confirmationTag: Uint8Array;
  signerIndex: LeafIndex;
}

export interface FramedContentTBS {
  protocolVersion: ProtocolVersion;
  wireFormat: WireFormat;
  content: FramedContent;
  context?: GroupContext;
}

export interface BasicCredential {
  identity: Uint8Array;
}

export interface RequiredCapabilities {
  extensions: ExtensionType[];
  proposals: ProposalType[];
  credentials: CredentialType[];
}

export interface ExternalSender {
  signatureKey: SignaturePublicKey;
  credential: Credential;
}

export interface RatchetTreeExtension {
  tree: RatchetNode[];
}

export interface MessageKeys {
  suite: CipherSuite;
  generation: bigint;
  handshakeKeys: {
    key: Uint8Array;
    nonce: Uint8Array;
  };
  applicationKeys: {
    key: Uint8Array;
    nonce: Uint8Array;
  };
  deriveKeyNonce(
    generation: bigint,
  ): Promise<{ key: Uint8Array; nonce: Uint8Array }>;
  key: Uint8Array; // Shortcut property for current key
  nonce: Uint8Array; // Shortcut property for current nonce
}

export const MLSMessageType = {
  Public: 1,
  Private: 2,
  Welcome: 3,
  GroupInfo: 4,
  KeyPackage: 5,
} as const;
