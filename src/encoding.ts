/**
 * Encoding and decoding functions for MLS wire format
 */

import { decodeVarint, encodeVarint } from "./crypto.ts";
import {
  type Capabilities,
  type CipherSuite,
  type Commit,
  ContentType,
  type Credential,
  CredentialType,
  type EncryptedGroupSecrets,
  type Epoch,
  type Extension,
  type ExtensionType,
  type FramedContent,
  type FramedContentAuthData,
  type FramedContentTBS,
  type GroupContext,
  type GroupInfo,
  type GroupSecrets,
  type HPKECiphertext,
  type HPKEPublicKey,
  type KeyPackage,
  type LeafNode,
  LeafNodeSource,
  type Lifetime,
  type MLSMessage,
  type ParentNode,
  type PreSharedKeyID,
  type PrivateMessage,
  type Proposal,
  type ProposalOrRef,
  type ProposalRef,
  ProposalType,
  type ProtocolVersion,
  PSKType,
  type PublicMessage,
  type ResumptionPSKUsage,
  type Sender,
  SenderType,
  type SignaturePublicKey,
  type UpdatePath,
  type UpdatePathNode,
  type Welcome,
  WireFormat,
} from "./types.ts";

/**
 * Encoder class for building binary data
 */
export class Encoder {
  private buffer: Uint8Array;
  private position: number;

  constructor(initialSize: number = 1024) {
    this.buffer = new Uint8Array(initialSize);
    this.position = 0;
  }

  private ensureCapacity(additionalBytes: number): void {
    const requiredSize = this.position + additionalBytes;
    if (requiredSize > this.buffer.length) {
      const newSize = Math.max(requiredSize, this.buffer.length * 2);
      const newBuffer = new Uint8Array(newSize);
      newBuffer.set(this.buffer);
      this.buffer = newBuffer;
    }
  }

  writeUint8(value: number): void {
    this.ensureCapacity(1);
    this.buffer[this.position++] = value;
  }

  writeUint16(value: number): void {
    this.ensureCapacity(2);
    const view = new DataView(this.buffer.buffer, this.buffer.byteOffset);
    view.setUint16(this.position, value, false); // big-endian
    this.position += 2;
  }

  writeUint32(value: number): void {
    this.ensureCapacity(4);
    const view = new DataView(this.buffer.buffer, this.buffer.byteOffset);
    view.setUint32(this.position, value, false); // big-endian
    this.position += 4;
  }

  writeUint64(value: bigint): void {
    this.ensureCapacity(8);
    const view = new DataView(this.buffer.buffer, this.buffer.byteOffset);
    view.setBigUint64(this.position, value, false); // big-endian
    this.position += 8;
  }

  writeBytes(bytes: Uint8Array): void {
    this.ensureCapacity(bytes.length);
    this.buffer.set(bytes, this.position);
    this.position += bytes.length;
  }

  writeVarintVector(data: Uint8Array): void {
    const lengthBytes = encodeVarint(data.length);
    this.writeBytes(lengthBytes);
    this.writeBytes(data);
  }

  writeFixedVector(data: Uint8Array): void {
    if (data.length > 255) {
      throw new Error("Fixed vector too long");
    }
    this.writeUint8(data.length);
    this.writeBytes(data);
  }

  finish(): Uint8Array {
    return this.buffer.slice(0, this.position);
  }

  // Alias for finish() to match expected API
  encode(): Uint8Array {
    return this.finish();
  }
}

/**
 * Decoder class for reading binary data
 */
export class Decoder {
  private buffer: Uint8Array;
  private position: number;

  constructor(buffer: Uint8Array) {
    this.buffer = buffer;
    this.position = 0;
  }

  private ensureBytes(count: number): void {
    if (this.position + count > this.buffer.length) {
      throw new Error("Not enough bytes");
    }
  }

  readUint8(): number {
    this.ensureBytes(1);
    return this.buffer[this.position++];
  }

  readUint16(): number {
    this.ensureBytes(2);
    const view = new DataView(this.buffer.buffer, this.buffer.byteOffset);
    const value = view.getUint16(this.position, false); // big-endian
    this.position += 2;
    return value;
  }

  readUint32(): number {
    this.ensureBytes(4);
    const view = new DataView(this.buffer.buffer, this.buffer.byteOffset);
    const value = view.getUint32(this.position, false); // big-endian
    this.position += 4;
    return value;
  }

  readUint64(): bigint {
    this.ensureBytes(8);
    const view = new DataView(this.buffer.buffer, this.buffer.byteOffset);
    const value = view.getBigUint64(this.position, false); // big-endian
    this.position += 8;
    return value;
  }

  readBytes(count: number): Uint8Array {
    this.ensureBytes(count);
    const bytes = this.buffer.slice(this.position, this.position + count);
    this.position += count;
    return bytes;
  }

  readVarintVector(): Uint8Array {
    const { value: length, bytesRead } = decodeVarint(
      this.buffer,
      this.position,
    );
    this.position += bytesRead;
    return this.readBytes(length);
  }

  readFixedVector(): Uint8Array {
    const length = this.readUint8();
    return this.readBytes(length);
  }

  hasMore(): boolean {
    return this.position < this.buffer.length;
  }

  remaining(): number {
    return this.buffer.length - this.position;
  }
}

// Encoding functions

export function encodeExtension(ext: Extension): Uint8Array {
  const encoder = new Encoder();
  encoder.writeUint16(ext.extensionType);
  encoder.writeVarintVector(ext.extensionData);
  return encoder.finish();
}

export function encodeExtensions(extensions: Extension[]): Uint8Array {
  const encoder = new Encoder();
  const extData = new Encoder();

  for (const ext of extensions) {
    const encoded = encodeExtension(ext);
    extData.writeBytes(encoded);
  }

  encoder.writeVarintVector(extData.finish());
  return encoder.finish();
}

export function encodeCredential(cred: Credential): Uint8Array {
  const encoder = new Encoder();
  encoder.writeUint16(cred.credentialType);

  switch (cred.credentialType) {
    case CredentialType.BASIC:
      if (!cred.identity) throw new Error("Basic credential requires identity");
      encoder.writeVarintVector(cred.identity);
      break;
    case CredentialType.X509:
      if (!cred.certificates) {
        throw new Error("X509 credential requires certificates");
      }
      const certEncoder = new Encoder();
      for (const cert of cred.certificates) {
        certEncoder.writeVarintVector(cert);
      }
      encoder.writeVarintVector(certEncoder.finish());
      break;
    default:
      throw new Error(`Unknown credential type: ${cred.credentialType}`);
  }

  return encoder.finish();
}

export function encodeCapabilities(cap: Capabilities): Uint8Array {
  const encoder = new Encoder();

  // Versions
  const versionsEncoder = new Encoder();
  for (const version of cap.versions) {
    versionsEncoder.writeUint16(version);
  }
  encoder.writeVarintVector(versionsEncoder.finish());

  // Cipher suites
  const suitesEncoder = new Encoder();
  for (const suite of cap.cipherSuites) {
    suitesEncoder.writeUint16(suite);
  }
  encoder.writeVarintVector(suitesEncoder.finish());

  // Extensions
  const extTypesEncoder = new Encoder();
  for (const extType of cap.extensions) {
    extTypesEncoder.writeUint16(extType);
  }
  encoder.writeVarintVector(extTypesEncoder.finish());

  // Proposals
  const proposalsEncoder = new Encoder();
  for (const proposal of cap.proposals) {
    proposalsEncoder.writeUint16(proposal);
  }
  encoder.writeVarintVector(proposalsEncoder.finish());

  // Credentials
  const credsEncoder = new Encoder();
  for (const credType of cap.credentials) {
    credsEncoder.writeUint16(credType);
  }
  encoder.writeVarintVector(credsEncoder.finish());

  return encoder.finish();
}

export function encodeLifetime(lifetime: Lifetime): Uint8Array {
  const encoder = new Encoder();
  encoder.writeUint64(lifetime.notBefore);
  encoder.writeUint64(lifetime.notAfter);
  return encoder.finish();
}

export function encodeLeafNode(node: LeafNode): Uint8Array {
  const encoder = new Encoder();

  encoder.writeVarintVector(node.encryptionKey);
  encoder.writeVarintVector(node.signatureKey);
  encoder.writeBytes(encodeCredential(node.credential));
  encoder.writeBytes(encodeCapabilities(node.capabilities));
  encoder.writeUint8(node.leafNodeSource);

  switch (node.leafNodeSource) {
    case LeafNodeSource.KEY_PACKAGE:
      if (!node.lifetime) {
        throw new Error("KeyPackage leaf node requires lifetime");
      }
      encoder.writeBytes(encodeLifetime(node.lifetime));
      break;
    case LeafNodeSource.UPDATE:
      // No additional data
      break;
    case LeafNodeSource.COMMIT:
      if (!node.parentHash) {
        throw new Error("Commit leaf node requires parent hash");
      }
      encoder.writeVarintVector(node.parentHash);
      break;
  }

  encoder.writeBytes(encodeExtensions(node.extensions));
  encoder.writeVarintVector(node.signature || new Uint8Array(0));

  return encoder.finish();
}

export function encodeParentNode(node: ParentNode): Uint8Array {
  const encoder = new Encoder();

  encoder.writeVarintVector(node.encryptionKey);
  encoder.writeVarintVector(node.parentHash);

  // Encode unmerged leaves
  const leavesEncoder = new Encoder();
  for (const leafIndex of node.unmergedLeaves) {
    leavesEncoder.writeUint32(leafIndex);
  }
  encoder.writeVarintVector(leavesEncoder.finish());

  return encoder.finish();
}

export function encodeKeyPackage(kp: KeyPackage): Uint8Array {
  const encoder = new Encoder();

  encoder.writeUint16(kp.protocolVersion);
  encoder.writeUint16(kp.cipherSuite);
  encoder.writeVarintVector(kp.initKey);
  encoder.writeBytes(encodeLeafNode(kp.leafNode));
  encoder.writeBytes(encodeExtensions(kp.extensions));
  encoder.writeVarintVector(kp.signature);

  return encoder.finish();
}

export function encodeGroupContext(gc: GroupContext): Uint8Array {
  const encoder = new Encoder();

  encoder.writeUint16(gc.protocolVersion);
  encoder.writeUint16(gc.cipherSuite);
  encoder.writeVarintVector(gc.groupId);
  encoder.writeUint64(gc.epoch);
  encoder.writeVarintVector(gc.treeHash);
  encoder.writeVarintVector(gc.confirmedTranscriptHash);
  encoder.writeBytes(encodeExtensions(gc.extensions));

  return encoder.finish();
}

export function encodeSender(sender: Sender): Uint8Array {
  const encoder = new Encoder();
  encoder.writeUint8(sender.senderType);

  switch (sender.senderType) {
    case SenderType.MEMBER:
      if (sender.leafIndex === undefined) {
        throw new Error("Member sender requires leaf index");
      }
      encoder.writeUint32(sender.leafIndex);
      break;
    case SenderType.EXTERNAL:
      if (sender.senderIndex === undefined) {
        throw new Error("External sender requires sender index");
      }
      encoder.writeUint32(sender.senderIndex);
      break;
    case SenderType.NEW_MEMBER_COMMIT:
    case SenderType.NEW_MEMBER_PROPOSAL:
      // No additional data
      break;
  }

  return encoder.finish();
}

export function encodeProposal(proposal: Proposal): Uint8Array {
  const encoder = new Encoder();
  encoder.writeUint16(proposal.proposalType);

  switch (proposal.proposalType) {
    case ProposalType.ADD:
      if (!proposal.add) throw new Error("Add proposal requires add field");
      encoder.writeBytes(encodeKeyPackage(proposal.add.keyPackage));
      break;
    case ProposalType.UPDATE:
      if (!proposal.update) {
        throw new Error("Update proposal requires update field");
      }
      encoder.writeBytes(encodeLeafNode(proposal.update.leafNode));
      break;
    case ProposalType.REMOVE:
      if (!proposal.remove) {
        throw new Error("Remove proposal requires remove field");
      }
      encoder.writeUint32(proposal.remove.removed);
      break;
    case ProposalType.PSK:
      if (!proposal.psk) throw new Error("PSK proposal requires psk field");
      encoder.writeBytes(encodePreSharedKeyID(proposal.psk.psk));
      break;
    case ProposalType.REINIT:
      if (!proposal.reinit) {
        throw new Error("ReInit proposal requires reinit field");
      }
      encoder.writeVarintVector(proposal.reinit.groupId);
      encoder.writeUint16(proposal.reinit.protocolVersion);
      encoder.writeUint16(proposal.reinit.cipherSuite);
      encoder.writeBytes(encodeExtensions(proposal.reinit.extensions));
      break;
    case ProposalType.EXTERNAL_INIT:
      if (!proposal.externalInit) {
        throw new Error("ExternalInit proposal requires externalInit field");
      }
      encoder.writeVarintVector(proposal.externalInit.kemOutput);
      break;
    case ProposalType.GROUP_CONTEXT_EXTENSIONS:
      if (!proposal.groupContextExtensions) {
        throw new Error(
          "GroupContextExtensions proposal requires groupContextExtensions field",
        );
      }
      encoder.writeBytes(
        encodeExtensions(
          proposal.groupContextExtensions.groupContextExtensions,
        ),
      );
      break;
    default:
      throw new Error(`Unknown proposal type: ${proposal.proposalType}`);
  }

  return encoder.finish();
}

export function encodeProposalOrRef(proposalOrRef: ProposalOrRef): Uint8Array {
  const encoder = new Encoder();

  if (proposalOrRef.type === "proposal") {
    encoder.writeUint8(1); // Type 1 for inline proposal
    encoder.writeBytes(encodeProposal(proposalOrRef.proposal));
  } else {
    encoder.writeUint8(2); // Type 2 for reference
    encoder.writeFixedVector(proposalOrRef.reference);
  }

  return encoder.finish();
}

export function encodeHPKECiphertext(ct: HPKECiphertext): Uint8Array {
  const encoder = new Encoder();
  encoder.writeVarintVector(ct.kemOutput);
  encoder.writeVarintVector(ct.ciphertext);
  return encoder.finish();
}

export function encodeUpdatePathNode(node: UpdatePathNode): Uint8Array {
  const encoder = new Encoder();
  encoder.writeVarintVector(node.encryptionKey);

  // Encode encrypted path secrets (simplified as Uint8Array)
  const secretsEncoder = new Encoder();
  for (const secret of node.encryptedPathSecrets) {
    secretsEncoder.writeVarintVector(secret);
  }
  encoder.writeVarintVector(secretsEncoder.finish());

  return encoder.finish();
}

export function encodeUpdatePath(path: UpdatePath): Uint8Array {
  const encoder = new Encoder();
  encoder.writeBytes(encodeLeafNode(path.leafNode));

  // Encode nodes
  const nodesEncoder = new Encoder();
  for (const node of path.nodes) {
    nodesEncoder.writeBytes(encodeUpdatePathNode(node));
  }
  encoder.writeVarintVector(nodesEncoder.finish());

  return encoder.finish();
}

export function encodeCommit(commit: Commit): Uint8Array {
  const encoder = new Encoder();

  // Encode proposals as references
  const proposalsEncoder = new Encoder();
  for (const propRef of commit.proposals) {
    // For ProposalRef, we just encode the reference directly
    proposalsEncoder.writeVarintVector(propRef);
  }
  encoder.writeVarintVector(proposalsEncoder.finish());

  // Encode optional path
  if (commit.path) {
    encoder.writeUint8(1); // Present
    encoder.writeBytes(encodeUpdatePath(commit.path));
  } else {
    encoder.writeUint8(0); // Absent
  }

  return encoder.finish();
}

export function encodeFramedContent(content: FramedContent): Uint8Array {
  const encoder = new Encoder();

  encoder.writeVarintVector(content.groupId);
  encoder.writeUint64(content.epoch);
  encoder.writeBytes(encodeSender(content.sender));
  encoder.writeVarintVector(content.authenticatedData);
  encoder.writeUint8(content.contentType);

  switch (content.contentType) {
    case ContentType.APPLICATION:
      if (!content.applicationData) {
        throw new Error("Application content requires application data");
      }
      encoder.writeVarintVector(content.applicationData);
      break;
    case ContentType.PROPOSAL:
      if (!content.proposal) {
        throw new Error("Proposal content requires proposal");
      }
      encoder.writeBytes(encodeProposal(content.proposal));
      break;
    case ContentType.COMMIT:
      if (!content.commit) throw new Error("Commit content requires commit");
      encoder.writeBytes(encodeCommit(content.commit));
      break;
    default:
      throw new Error(`Unknown content type: ${content.contentType}`);
  }

  return encoder.finish();
}

export function encodeFramedContentAuthData(
  auth: FramedContentAuthData,
): Uint8Array {
  const encoder = new Encoder();

  encoder.writeVarintVector(auth.signature);

  if (auth.confirmationTag !== undefined) {
    encoder.writeBytes(auth.confirmationTag);
  }

  return encoder.finish();
}

export function encodePreSharedKeyID(pskId: PreSharedKeyID): Uint8Array {
  const encoder = new Encoder();
  encoder.writeUint8(pskId.pskType);

  switch (pskId.pskType) {
    case PSKType.EXTERNAL:
      if (!pskId.pskId) throw new Error("External PSK requires pskId");
      encoder.writeVarintVector(pskId.pskId);
      break;
    case PSKType.RESUMPTION:
      if (
        pskId.usage === undefined || !pskId.pskGroupId ||
        pskId.pskEpoch === undefined
      ) {
        throw new Error("Resumption PSK requires usage, group ID, and epoch");
      }
      encoder.writeUint8(pskId.usage);
      encoder.writeVarintVector(pskId.pskGroupId);
      encoder.writeUint64(pskId.pskEpoch);
      break;
    default:
      throw new Error(`Unknown PSK type: ${pskId.pskType}`);
  }

  encoder.writeVarintVector(pskId.pskNonce);
  return encoder.finish();
}

// Decoding functions

export function decodeExtension(decoder: Decoder): Extension {
  const extensionType = decoder.readUint16();
  const extensionData = decoder.readVarintVector();
  return { extensionType, extensionData };
}

export function decodeExtensions(decoder: Decoder): Extension[] {
  const data = decoder.readVarintVector();
  const extDecoder = new Decoder(data);
  const extensions: Extension[] = [];

  while (extDecoder.hasMore()) {
    extensions.push(decodeExtension(extDecoder));
  }

  return extensions;
}

export function decodeCredential(decoder: Decoder): Credential {
  const credentialType = decoder.readUint16();

  switch (credentialType) {
    case CredentialType.BASIC:
      return {
        credentialType,
        identity: decoder.readVarintVector(),
      };
    case CredentialType.X509:
      const certData = decoder.readVarintVector();
      const certDecoder = new Decoder(certData);
      const certificates: Uint8Array[] = [];
      while (certDecoder.hasMore()) {
        certificates.push(certDecoder.readVarintVector());
      }
      return {
        credentialType,
        certificates,
      };
    default:
      throw new Error(`Unknown credential type: ${credentialType}`);
  }
}

export function decodeCapabilities(decoder: Decoder): Capabilities {
  // Versions
  const versionsData = decoder.readVarintVector();
  const versionsDecoder = new Decoder(versionsData);
  const versions: ProtocolVersion[] = [];
  while (versionsDecoder.hasMore()) {
    versions.push(versionsDecoder.readUint16());
  }

  // Cipher suites
  const suitesData = decoder.readVarintVector();
  const suitesDecoder = new Decoder(suitesData);
  const cipherSuites: CipherSuite[] = [];
  while (suitesDecoder.hasMore()) {
    cipherSuites.push(suitesDecoder.readUint16());
  }

  // Extensions
  const extData = decoder.readVarintVector();
  const extDecoder = new Decoder(extData);
  const extensions: ExtensionType[] = [];
  while (extDecoder.hasMore()) {
    extensions.push(extDecoder.readUint16());
  }

  // Proposals
  const propData = decoder.readVarintVector();
  const propDecoder = new Decoder(propData);
  const proposals: ProposalType[] = [];
  while (propDecoder.hasMore()) {
    proposals.push(propDecoder.readUint16());
  }

  // Credentials
  const credData = decoder.readVarintVector();
  const credDecoder = new Decoder(credData);
  const credentials: CredentialType[] = [];
  while (credDecoder.hasMore()) {
    credentials.push(credDecoder.readUint16());
  }

  return {
    versions,
    cipherSuites,
    extensions,
    proposals,
    credentials,
  };
}

export function decodeLifetime(decoder: Decoder): Lifetime {
  const notBefore = decoder.readUint64();
  const notAfter = decoder.readUint64();
  return { notBefore, notAfter };
}

export function decodeLeafNode(decoder: Decoder): LeafNode {
  const encryptionKey = decoder.readVarintVector();
  const signatureKey = decoder.readVarintVector();
  const credential = decodeCredential(decoder);
  const capabilities = decodeCapabilities(decoder);
  const leafNodeSource = decoder.readUint8() as LeafNodeSource;

  let lifetime: Lifetime | undefined;
  let parentHash: Uint8Array | undefined;

  switch (leafNodeSource) {
    case LeafNodeSource.KEY_PACKAGE:
      lifetime = decodeLifetime(decoder);
      break;
    case LeafNodeSource.UPDATE:
      // No additional data
      break;
    case LeafNodeSource.COMMIT:
      parentHash = decoder.readVarintVector();
      break;
  }

  const extensions = decodeExtensions(decoder);
  const signature = decoder.readVarintVector();

  return {
    encryptionKey,
    signatureKey,
    credential,
    capabilities,
    leafNodeSource,
    lifetime,
    parentHash,
    extensions,
    signature,
  };
}

export function decodeParentNode(decoder: Decoder): ParentNode {
  const encryptionKey = decoder.readVarintVector();
  const parentHash = decoder.readVarintVector();

  const leavesData = decoder.readVarintVector();
  const leavesDecoder = new Decoder(leavesData);
  const unmergedLeaves: number[] = [];

  while (leavesDecoder.hasMore()) {
    unmergedLeaves.push(leavesDecoder.readUint32());
  }

  return {
    encryptionKey,
    parentHash,
    unmergedLeaves,
  };
}

export function decodeKeyPackage(data: Uint8Array): KeyPackage {
  const decoder = new Decoder(data);

  const protocolVersion = decoder.readUint16();
  const cipherSuite = decoder.readUint16();
  const initKey = decoder.readVarintVector();
  const leafNode = decodeLeafNode(decoder);
  const extensions = decodeExtensions(decoder);
  const signature = decoder.readVarintVector();

  return {
    protocolVersion,
    cipherSuite,
    initKey,
    leafNode,
    extensions,
    signature,
  };
}

export function decodeGroupContext(data: Uint8Array): GroupContext {
  const decoder = new Decoder(data);

  const protocolVersion = decoder.readUint16();
  const cipherSuite = decoder.readUint16();
  const groupId = decoder.readVarintVector();
  const epoch = decoder.readUint64();
  const treeHash = decoder.readVarintVector();
  const confirmedTranscriptHash = decoder.readVarintVector();
  const extensions = decodeExtensions(decoder);

  return {
    protocolVersion,
    cipherSuite,
    groupId,
    epoch,
    treeHash,
    confirmedTranscriptHash,
    extensions,
  };
}

/**
 * Encode LeafNodeTBS for signing
 * This omits the signature field as per RFC 9420
 */
export function encodeLeafNodeTBS(node: LeafNode): Uint8Array {
  const encoder = new Encoder();

  encoder.writeVarintVector(node.encryptionKey);
  encoder.writeVarintVector(node.signatureKey);
  encoder.writeBytes(encodeCredential(node.credential));
  encoder.writeBytes(encodeCapabilities(node.capabilities));
  encoder.writeUint8(node.leafNodeSource);

  switch (node.leafNodeSource) {
    case LeafNodeSource.KEY_PACKAGE:
      if (!node.lifetime) {
        throw new Error("KeyPackage leaf node requires lifetime");
      }
      encoder.writeBytes(encodeLifetime(node.lifetime));
      break;
    case LeafNodeSource.UPDATE:
      // No additional data
      break;
    case LeafNodeSource.COMMIT:
      if (!node.parentHash) {
        throw new Error("Commit leaf node requires parent hash");
      }
      encoder.writeVarintVector(node.parentHash);
      break;
  }

  encoder.writeBytes(encodeExtensions(node.extensions));
  // Note: signature field is omitted for TBS

  return encoder.finish();
}

/**
 * Encode KeyPackageTBS for signing
 * This omits the signature field as per RFC 9420
 */
export function encodeKeyPackageTBS(kp: KeyPackage): Uint8Array {
  const encoder = new Encoder();

  encoder.writeUint16(kp.protocolVersion);
  encoder.writeUint16(kp.cipherSuite);
  encoder.writeVarintVector(kp.initKey);
  encoder.writeBytes(encodeLeafNode(kp.leafNode));
  encoder.writeBytes(encodeExtensions(kp.extensions));
  // Note: signature field is omitted for TBS

  return encoder.finish();
}

/**
 * Decode FramedContent from bytes
 */
export function decodeFramedContent(data: Uint8Array): FramedContent {
  const decoder = new Decoder(data);

  const groupId = decoder.readVarintVector();
  const epoch = decoder.readUint64();
  const sender = decodeSender(decoder);
  const authenticatedData = decoder.readVarintVector();
  const contentType = decoder.readUint8() as ContentType;

  const result: FramedContent = {
    groupId,
    epoch,
    sender,
    authenticatedData,
    contentType,
  };

  switch (contentType) {
    case ContentType.APPLICATION:
      result.applicationData = decoder.readVarintVector();
      break;
    case ContentType.PROPOSAL:
      result.proposal = decodeProposal(decoder);
      break;
    case ContentType.COMMIT:
      result.commit = decodeCommit(decoder);
      break;
    default:
      throw new Error(`Unknown content type: ${contentType}`);
  }

  return result;
}

/**
 * Decode Sender from decoder
 */
function decodeSender(decoder: Decoder): Sender {
  const senderType = decoder.readUint8() as SenderType;

  let leafIndex: number | undefined;
  let senderIndex: number | undefined;

  switch (senderType) {
    case SenderType.MEMBER:
      leafIndex = decoder.readUint32();
      break;
    case SenderType.EXTERNAL:
      senderIndex = decoder.readUint32();
      break;
    case SenderType.NEW_MEMBER_COMMIT:
    case SenderType.NEW_MEMBER_PROPOSAL:
      // No additional data
      break;
  }

  return {
    senderType,
    leafIndex,
    senderIndex,
  };
}

/**
 * Decode Proposal from decoder
 */
function decodeProposal(decoder: Decoder): Proposal {
  const proposalType = decoder.readUint16() as ProposalType;

  const result: Proposal = {
    proposalType,
  };

  switch (proposalType) {
    case ProposalType.ADD:
      const keyPackageBytes = decoder.readBytes(decoder.remaining());
      result.add = { keyPackage: decodeKeyPackage(keyPackageBytes) };
      break;
    case ProposalType.UPDATE:
      result.update = { leafNode: decodeLeafNode(decoder) };
      break;
    case ProposalType.REMOVE:
      result.remove = { removed: decoder.readUint32() };
      break;
    // Add other proposal types as needed
    default:
      throw new Error(`Unsupported proposal type: ${proposalType}`);
  }

  return result;
}

/**
 * Decode Commit from decoder
 */
function decodeCommit(decoder: Decoder): Commit {
  const proposalsData = decoder.readVarintVector();
  const proposalsDecoder = new Decoder(proposalsData);
  const proposals: ProposalRef[] = [];

  while (proposalsDecoder.hasMore()) {
    proposals.push(proposalsDecoder.readBytes(32)); // Assuming 32-byte refs
  }

  const hasPath = decoder.readUint8();
  let path: UpdatePath | undefined;

  if (hasPath === 1) {
    path = decodeUpdatePath(decoder);
  }

  return {
    proposals,
    path,
  };
}

/**
 * Decode UpdatePath from decoder
 */
function decodeUpdatePath(decoder: Decoder): UpdatePath {
  const leafNode = decodeLeafNode(decoder);
  
  const nodesData = decoder.readVarintVector();
  const nodesDecoder = new Decoder(nodesData);
  const nodes: UpdatePathNode[] = [];

  while (nodesDecoder.hasMore()) {
    nodes.push(decodeUpdatePathNode(nodesDecoder));
  }

  return {
    leafNode,
    nodes,
  };
}

/**
 * Decode UpdatePathNode from decoder  
 */
function decodeUpdatePathNode(decoder: Decoder): UpdatePathNode {
  const encryptionKey = decoder.readVarintVector();
  
  const secretsData = decoder.readVarintVector();
  const secretsDecoder = new Decoder(secretsData);
  const encryptedPathSecrets: Uint8Array[] = [];

  while (secretsDecoder.hasMore()) {
    encryptedPathSecrets.push(secretsDecoder.readVarintVector());
  }

  return {
    encryptionKey,
    encryptedPathSecrets,
  };
}

/**
 * Decode HPKECiphertext from decoder
 */
function decodeHPKECiphertext(decoder: Decoder): HPKECiphertext {
  const kemOutput = decoder.readVarintVector();
  const ciphertext = decoder.readVarintVector();
  return { kemOutput, ciphertext };
}

/**
 * Encode GroupInfo
 */
export function encodeGroupInfo(groupInfo: GroupInfo): Uint8Array {
  const encoder = new Encoder();

  encoder.writeBytes(encodeGroupContext(groupInfo.groupContext));
  encoder.writeBytes(encodeExtensions(groupInfo.extensions));
  encoder.writeVarintVector(groupInfo.confirmationTag);
  encoder.writeUint32(groupInfo.signerIndex);
  // Note: signature would be added separately

  return encoder.finish();
}

/**
 * Decode GroupInfo
 */
export function decodeGroupInfo(data: Uint8Array): GroupInfo {
  const decoder = new Decoder(data);

  const groupContextData = decoder.readVarintVector();
  const groupContext = decodeGroupContext(groupContextData);
  const extensions = decodeExtensions(decoder);
  const confirmationTag = decoder.readVarintVector();
  const signerIndex = decoder.readUint32();
  // Note: signature would be decoded separately if present

  return {
    groupContext,
    extensions,
    confirmationTag,
    signerIndex,
    signature: new Uint8Array(0), // Placeholder - should be computed during signing
  };
}

/**
 * Encode GroupSecrets 
 */
export function encodeGroupSecrets(secrets: GroupSecrets): Uint8Array {
  const encoder = new Encoder();

  encoder.writeVarintVector(secrets.joinerSecret);
  
  if (secrets.pathSecret) {
    encoder.writeUint8(1);
    encoder.writeVarintVector(secrets.pathSecret);
  } else {
    encoder.writeUint8(0);
  }

  // Encode PSKs
  const psksEncoder = new Encoder();
  for (const psk of secrets.psks) {
    psksEncoder.writeBytes(encodePreSharedKeyID(psk));
  }
  encoder.writeVarintVector(psksEncoder.finish());

  return encoder.finish();
}

/**
 * Encode MLSMessage
 */
export function encodeMLSMessage(message: MLSMessage): Uint8Array {
  const encoder = new Encoder();

  encoder.writeUint16(message.protocolVersion);
  encoder.writeUint8(message.wireFormat);

  switch (message.wireFormat) {
    case WireFormat.PublicMessage:
      const pub = message.message as PublicMessage;
      encoder.writeBytes(encodeFramedContent(pub.content));
      encoder.writeVarintVector(pub.authTag);
      break;
    case WireFormat.PrivateMessage:
      const priv = message.message as PrivateMessage;
      encoder.writeVarintVector(priv.groupId);
      encoder.writeUint64(priv.epoch);
      encoder.writeUint8(priv.contentType);
      encoder.writeVarintVector(priv.authenticatedData);
      encoder.writeVarintVector(priv.encryptedSenderData);
      encoder.writeUint64(priv.generation);
      break;
    default:
      throw new Error(`Unknown wire format: ${message.wireFormat}`);
  }

  return encoder.finish();
}

/**
 * Decode MLSMessage from bytes
 */
export function decodeMLSMessage(data: Uint8Array): MLSMessage {
  const decoder = new Decoder(data);

  const protocolVersion = decoder.readUint16();
  const wireFormat = decoder.readUint8() as WireFormat;

  let message: PublicMessage | PrivateMessage;

  switch (wireFormat) {
    case WireFormat.PublicMessage:
      const contentLength = decoder.remaining() - 4; // Assume last 4 bytes are auth tag length prefix
      const contentBytes = decoder.readBytes(contentLength);
      const content = decodeFramedContent(contentBytes);
      const authTag = decoder.readVarintVector();
      message = { content, authTag } as PublicMessage;
      break;
    case WireFormat.PrivateMessage:
      const groupId = decoder.readVarintVector();
      const epoch = decoder.readUint64();
      const contentType = decoder.readUint8() as ContentType;
      const authenticatedData = decoder.readVarintVector();
      const encryptedSenderData = decoder.readVarintVector();
      const generation = decoder.readUint64();
      message = {
        groupId,
        epoch,
        contentType,
        authenticatedData,
        encryptedSenderData,
        generation,
      } as PrivateMessage;
      break;
    default:
      throw new Error(`Unknown wire format: ${wireFormat}`);
  }

  return {
    protocolVersion,
    wireFormat,
    message,
  };
}

/**
 * Encode FramedContentTBS (to-be-signed)
 */
export function encodeFramedContentTBS(tbs: FramedContentTBS): Uint8Array {
  const encoder = new Encoder();

  encoder.writeUint16(tbs.protocolVersion);
  encoder.writeUint8(tbs.wireFormat);
  encoder.writeBytes(encodeFramedContent(tbs.content));
  if (tbs.context) {
    encoder.writeBytes(encodeGroupContext(tbs.context));
  }

  return encoder.finish();
}
