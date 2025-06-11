/**
 * MLS Message Framing and Processing
 *
 * This module implements the message layer for MLS, handling the secure packaging
 * and processing of both application and protocol messages using HPKE encryption.
 * 
 * Key components:
 * - PublicMessage: Unencrypted messages (proposals, commits)
 * - PrivateMessage: HPKE-encrypted application data
 * - Message authentication and validation
 * - Replay protection mechanisms
 */

import {
  type CipherSuite,
  ContentType,
  type FramedContent,
  type FramedContentTBS,
  type GroupContext,
  type MLSMessage,
  type PrivateMessage,
  type PublicMessage,
  ProtocolVersion,
  type Sender,
  type SenderType,
  WireFormat,
} from "./types.ts";

import {
  aeadDecrypt,
  aeadEncrypt,
  hash,
  signWithLabel,
  verifyWithLabel,
} from "./crypto.ts";

import type {
  contextOpen,
  contextSeal,
  setupBaseR,
  setupBaseS,
  HPKEContext,
} from "./hpke.ts";

import {
  decodeFramedContent,
  decodeMLSMessage,
  encodeFramedContent,
  encodeFramedContentTBS,
  encodeMLSMessage,
} from "./encoding.ts";

/**
 * Message processing context for encrypted messages
 */
export interface MessageContext {
  cipherSuite: CipherSuite;
  epoch: bigint;
  groupId: Uint8Array;
  senderDataSecret: Uint8Array;
  encryptionSecret: Uint8Array;
}

/**
 * Result of processing an encrypted message
 */
export interface MessageResult {
  framedContent: FramedContent;
  generation: bigint;
  reusedNonce: boolean;
}

/**
 * Message encryption/decryption engine
 */
export class MessageProcessor {
  private context: MessageContext;
  private generationCounter: bigint;
  private usedNonces: Set<string>;

  constructor(context: MessageContext) {
    this.context = context;
    this.generationCounter = 0n;
    this.usedNonces = new Set();
  }

  /**
   * Create a PublicMessage (unencrypted) for proposals and commits
   */
  createPublicMessage(
    content: FramedContent,
    signature: Uint8Array,
  ): MLSMessage {
    const publicMessage: PublicMessage = {
      content,
      authTag: signature,
    };

    return {
      protocolVersion: ProtocolVersion.MLS10,
      wireFormat: WireFormat.PublicMessage,
      message: publicMessage,
    };
  }

  /**
   * Create a PrivateMessage (HPKE-encrypted) for application data
   */
  async createPrivateMessage(
    content: FramedContent,
    additionalData?: Uint8Array,
  ): Promise<MLSMessage> {
    // Encode the framed content
    const contentBytes = encodeFramedContent(content);

    // Create sender data (simplified - in full implementation would include more metadata)
    const senderData = this.createSenderData(content.sender);

    // Encrypt content using application ratchet
    const generation = this.generationCounter++;
    const { ciphertext, nonce } = await this.encryptContent(
      contentBytes,
      senderData,
      generation,
    );

    const privateMessage: PrivateMessage = {
      groupId: this.context.groupId,
      epoch: this.context.epoch,
      contentType: content.contentType,
      authenticatedData: additionalData || new Uint8Array(0),
      encryptedSenderData: ciphertext,
      generation,
    };

    // Store nonce to prevent reuse
    this.usedNonces.add(this.nonceToString(nonce));

    return {
      protocolVersion: ProtocolVersion.MLS10,
      wireFormat: WireFormat.PrivateMessage,
      message: privateMessage,
    };
  }

  /**
   * Process a PublicMessage (verify signature and extract content)
   */
  processPublicMessage(
    mlsMessage: MLSMessage,
    senderPublicKey: Uint8Array,
    groupContext: GroupContext,
  ): FramedContent {
    if (mlsMessage.wireFormat !== WireFormat.PublicMessage) {
      throw new Error("Expected PublicMessage");
    }

    const publicMessage = mlsMessage.message as PublicMessage;
    const content = publicMessage.content;

    // Verify signature
    if (!this.verifyPublicMessageSignature(
      content,
      publicMessage.authTag,
      senderPublicKey,
      groupContext,
    )) {
      throw new Error("Invalid message signature");
    }

    // Validate epoch
    if (content.epoch !== this.context.epoch) {
      throw new Error(`Message epoch mismatch: expected ${this.context.epoch}, got ${content.epoch}`);
    }

    // Validate group ID
    if (!this.arraysEqual(content.groupId, this.context.groupId)) {
      throw new Error("Message group ID mismatch");
    }

    return content;
  }

  /**
   * Process a PrivateMessage (decrypt and extract content)
   */
  async processPrivateMessage(
    mlsMessage: MLSMessage,
  ): Promise<MessageResult> {
    if (mlsMessage.wireFormat !== WireFormat.PrivateMessage) {
      throw new Error("Expected PrivateMessage");
    }

    const privateMessage = mlsMessage.message as PrivateMessage;

    // Validate epoch
    if (privateMessage.epoch !== this.context.epoch) {
      throw new Error(`Message epoch mismatch: expected ${this.context.epoch}, got ${privateMessage.epoch}`);
    }

    // Validate group ID
    if (!this.arraysEqual(privateMessage.groupId, this.context.groupId)) {
      throw new Error("Message group ID mismatch");
    }

    // Decrypt content
    const { contentBytes, nonce, reusedNonce } = await this.decryptContent(
      privateMessage.encryptedSenderData,
      privateMessage.authenticatedData,
      privateMessage.generation,
    );

    // Decode framed content
    const framedContent = decodeFramedContent(contentBytes);

    // Validate content type matches
    if (framedContent.contentType !== privateMessage.contentType) {
      throw new Error("Content type mismatch");
    }

    // Store nonce to prevent reuse (if not already used)
    if (!reusedNonce) {
      this.usedNonces.add(this.nonceToString(nonce));
    }

    return {
      framedContent,
      generation: privateMessage.generation,
      reusedNonce,
    };
  }

  /**
   * Sign a FramedContent for PublicMessage
   */
  signFramedContent(
    content: FramedContent,
    privateKey: Uint8Array,
    groupContext: GroupContext,
  ): Uint8Array {
    // Create FramedContentTBS
    const tbs: FramedContentTBS = {
      protocolVersion: ProtocolVersion.MLS10,
      wireFormat: WireFormat.PublicMessage,
      content,
      context: groupContext,
    };

    const tbsBytes = encodeFramedContentTBS(tbs);

    return signWithLabel(
      this.context.cipherSuite,
      privateKey,
      "FramedContentTBS", 
      tbsBytes,
    );
  }

  /**
   * Update the message context (for epoch changes)
   */
  updateContext(newContext: MessageContext): void {
    this.context = newContext;
    this.generationCounter = 0n;
    this.usedNonces.clear();
  }

  /**
   * Get current generation counter
   */
  getGeneration(): bigint {
    return this.generationCounter;
  }

  /**
   * Check if a nonce has been used (replay protection)
   */
  isNonceUsed(nonce: Uint8Array): boolean {
    return this.usedNonces.has(this.nonceToString(nonce));
  }

  // Private helper methods

  private createSenderData(sender: Sender): Uint8Array {
    // Simplified sender data - in full implementation would be more complex
    const senderBytes = new Uint8Array(8);
    const view = new DataView(senderBytes.buffer);
    
    view.setUint32(0, sender.senderType, false);
    if (sender.leafIndex !== undefined) {
      view.setUint32(4, sender.leafIndex, false);
    }
    
    return senderBytes;
  }

  private async encryptContent(
    content: Uint8Array,
    senderData: Uint8Array,
    generation: bigint,
  ): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
    // Derive message key from encryption secret and generation
    const messageKey = this.deriveMessageKey(generation);
    
    // Create nonce from generation and sender data
    const nonce = this.createNonce(generation, senderData);

    // AEAD encrypt
    const ciphertext = aeadEncrypt(
      this.context.cipherSuite,
      messageKey,
      nonce,
      content,
      senderData, // AAD
    );

    return { ciphertext, nonce };
  }

  private async decryptContent(
    ciphertext: Uint8Array,
    aad: Uint8Array,
    generation: bigint,
  ): Promise<{ contentBytes: Uint8Array; nonce: Uint8Array; reusedNonce: boolean }> {
    // Derive message key from encryption secret and generation  
    const messageKey = this.deriveMessageKey(generation);
    
    // Reconstruct nonce (simplified - real implementation would extract from message)
    const nonce = this.createNonce(generation, aad);

    // Check for nonce reuse
    const reusedNonce = this.isNonceUsed(nonce);
    if (reusedNonce) {
      console.warn(`Possible replay attack: nonce reuse detected for generation ${generation}`);
    }

    // AEAD decrypt
    const contentBytes = aeadDecrypt(
      this.context.cipherSuite,
      messageKey,
      nonce,
      ciphertext,
      aad,
    );

    return { contentBytes, nonce, reusedNonce };
  }

  private deriveMessageKey(generation: bigint): Uint8Array {
    // Simplified key derivation - real implementation would use proper KDF tree
    const generationBytes = new Uint8Array(8);
    const view = new DataView(generationBytes.buffer);
    view.setBigUint64(0, generation, false);

    const input = new Uint8Array(this.context.encryptionSecret.length + generationBytes.length);
    input.set(this.context.encryptionSecret, 0);
    input.set(generationBytes, this.context.encryptionSecret.length);

    return hash(this.context.cipherSuite, input).slice(0, this.getKeySize());
  }

  private createNonce(generation: bigint, senderData: Uint8Array): Uint8Array {
    const nonceSize = this.getNonceSize();
    const nonce = new Uint8Array(nonceSize);
    
    // Simple nonce construction: generation + hash of sender data
    const generationBytes = new Uint8Array(8);
    const view = new DataView(generationBytes.buffer);
    view.setBigUint64(0, generation, false);

    const senderHash = hash(this.context.cipherSuite, senderData);
    
    // XOR generation bytes with sender hash prefix
    for (let i = 0; i < Math.min(8, nonceSize); i++) {
      nonce[i] = generationBytes[i] ^ (senderHash[i] || 0);
    }

    return nonce;
  }

  private verifyPublicMessageSignature(
    content: FramedContent,
    signature: Uint8Array,
    publicKey: Uint8Array,
    groupContext: GroupContext,
  ): boolean {
    const tbs: FramedContentTBS = {
      protocolVersion: ProtocolVersion.MLS10,
      wireFormat: WireFormat.PublicMessage,
      content,
      context: groupContext,
    };

    const tbsBytes = encodeFramedContentTBS(tbs);

    return verifyWithLabel(
      this.context.cipherSuite,
      publicKey,
      "FramedContentTBS",
      tbsBytes,
      signature,
    );
  }

  private getKeySize(): number {
    // Return key size based on cipher suite
    switch (this.context.cipherSuite) {
      case 0x0001: // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 
        return 16;
      case 0x0002: // MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        return 16;
      case 0x0003: // MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        return 32;
      case 0x0004: // MLS_256_DHKEMP384_AES256GCM_SHA384_P384
        return 32;
      case 0x0005: // MLS_256_DHKEMP521_AES256GCM_SHA512_P521
        return 32;
      case 0x0006: // MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        return 32;
      case 0x0007: // MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
        return 32;
      default:
        throw new Error(`Unsupported cipher suite: ${this.context.cipherSuite}`);
    }
  }

  private getNonceSize(): number {
    // Return nonce size based on cipher suite
    switch (this.context.cipherSuite) {
      case 0x0001: // AES128GCM
      case 0x0002:
      case 0x0004: // AES256GCM  
      case 0x0005:
      case 0x0006:
        return 12; // GCM nonce size
      case 0x0003: // ChaCha20Poly1305
      case 0x0007:
        return 12; // ChaCha20Poly1305 nonce size
      default:
        throw new Error(`Unsupported cipher suite: ${this.context.cipherSuite}`);
    }
  }

  private arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  private nonceToString(nonce: Uint8Array): string {
    return Array.from(nonce)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }
}

/**
 * Utility functions for message processing
 */

/**
 * Parse an MLSMessage from bytes
 */
export function parseMLSMessage(bytes: Uint8Array): MLSMessage {
  return decodeMLSMessage(bytes);
}

/**
 * Serialize an MLSMessage to bytes
 */
export function serializeMLSMessage(message: MLSMessage): Uint8Array {
  return encodeMLSMessage(message);
}

/**
 * Create a message processor for a given context
 */
export function createMessageProcessor(context: MessageContext): MessageProcessor {
  return new MessageProcessor(context);
}

/**
 * Validate message format and basic structure
 */
export function validateMLSMessage(message: MLSMessage): boolean {
  try {
    // Check protocol version
    if (message.protocolVersion !== ProtocolVersion.MLS10) {
      return false;
    }

    // Check wire format is valid
    if (message.wireFormat !== WireFormat.PublicMessage && 
        message.wireFormat !== WireFormat.PrivateMessage) {
      return false;
    }

    // Basic structure validation based on wire format
    if (message.wireFormat === WireFormat.PublicMessage) {
      const pub = message.message as PublicMessage;
      return pub.content !== undefined && pub.authTag !== undefined;
    } else {
      const priv = message.message as PrivateMessage;
      return priv.groupId !== undefined && 
             priv.epoch !== undefined &&
             priv.contentType !== undefined &&
             priv.encryptedSenderData !== undefined;
    }
  } catch {
    return false;
  }
}

/**
 * Extract epoch from any message type
 */
export function getMessageEpoch(message: MLSMessage): bigint {
  if (message.wireFormat === WireFormat.PublicMessage) {
    const pub = message.message as PublicMessage;
    return pub.content.epoch;
  } else {
    const priv = message.message as PrivateMessage;
    return priv.epoch;
  }
}

/**
 * Extract group ID from any message type  
 */
export function getMessageGroupId(message: MLSMessage): Uint8Array {
  if (message.wireFormat === WireFormat.PublicMessage) {
    const pub = message.message as PublicMessage;
    return pub.content.groupId;
  } else {
    const priv = message.message as PrivateMessage;
    return priv.groupId;
  }
}

/**
 * Check if message is application data
 */
export function isApplicationMessage(message: MLSMessage): boolean {
  if (message.wireFormat === WireFormat.PublicMessage) {
    const pub = message.message as PublicMessage;
    return pub.content.contentType === ContentType.APPLICATION;
  } else {
    const priv = message.message as PrivateMessage;
    return priv.contentType === ContentType.APPLICATION;
  }
}

/**
 * Check if message is a protocol message (proposal/commit)
 */
export function isProtocolMessage(message: MLSMessage): boolean {
  if (message.wireFormat === WireFormat.PublicMessage) {
    const pub = message.message as PublicMessage;
    return pub.content.contentType === ContentType.PROPOSAL ||
           pub.content.contentType === ContentType.COMMIT;
  } else {
    // Private messages are typically application data
    return false;
  }
}