/**
 * MLS (Message Layer Security) Protocol Implementation for Deno
 * Based on RFC 9420
 */

// Re-export all types
export * from "./types.ts";

// Re-export crypto utilities
export * from "./crypto.ts";

// Re-export encoding/decoding
export * from "./encoding.ts";

// Re-export storage (main interface)
export type {
  MLSStorage,
  StoredEpochSecrets,
  StoredGroup,
  StoredKeyPackage,
} from "./storage.ts";
export { createStorage } from "./storage.ts";

// Re-export memory storage (specific implementation)
export { InMemoryMLSStorage } from "./storage-memory.ts";

// Re-export ratchet tree
export * from "./ratchet-tree.ts";

// Re-export key schedule (avoiding MessageKeys conflict)
export { type EpochSecrets, KeySchedule, SecretTree } from "./key-schedule.ts";

// Re-export client
export * from "./client.ts";

// Re-export HPKE (avoiding HPKECiphertext conflict)
export {
  contextExport,
  contextOpen,
  contextSeal,
  open,
  seal,
  setupBaseR,
  setupBaseS,
  setupPSKR,
  setupPSKS,
} from "./hpke.ts";
export type { HPKEContext } from "./hpke.ts";

// Re-export group operations
export * from "./group.ts";

// Re-export message processing
export * from "./message.ts";

// Version
export const VERSION = "0.1.0";
