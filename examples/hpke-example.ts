/**
 * HPKE Usage Example
 *
 * This example demonstrates how to use the HPKE implementation
 * for encryption and decryption in the MLS context.
 */

import {
  CipherSuite,
  contextExport,
  contextOpen,
  contextSeal,
  generateHPKEKeyPair,
  open,
  seal,
  setupBaseR,
  setupBaseS,
} from "../src/mod.ts";

// Choose a cipher suite
const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

console.log("=== HPKE Example ===\n");

// Generate a key pair for the receiver
const receiverKeyPair = generateHPKEKeyPair(suite);
console.log("Generated receiver key pair");
console.log("Public key length:", receiverKeyPair.publicKey.length);

// Example 1: Single-shot encryption
console.log("\n--- Single-shot Encryption ---");

const message = "Hello, MLS with HPKE!";
const plaintext = new TextEncoder().encode(message);
const info = new TextEncoder().encode("example info");
const aad = new TextEncoder().encode("example aad");

// Encrypt
const encrypted = seal(
  suite,
  receiverKeyPair.publicKey,
  info,
  aad,
  plaintext,
);

console.log("Encrypted message");
console.log("Encapsulated key length:", encrypted.encappedKey.length);
console.log("Ciphertext length:", encrypted.ciphertext.length);

// Decrypt
const decrypted = open(
  suite,
  encrypted.encappedKey,
  receiverKeyPair.privateKey,
  receiverKeyPair.publicKey,
  info,
  aad,
  encrypted.ciphertext,
);

console.log("Decrypted message:", new TextDecoder().decode(decrypted));

// Example 2: Streaming encryption
console.log("\n--- Streaming Encryption ---");

// Setup sender context
const { encappedKey, context: senderContext } = setupBaseS(
  suite,
  receiverKeyPair.publicKey,
  info,
);

// Setup receiver context
const receiverContext = setupBaseR(
  suite,
  encappedKey,
  receiverKeyPair.privateKey,
  receiverKeyPair.publicKey,
  info,
);

// Send multiple messages
const messages = [
  "First streaming message",
  "Second streaming message",
  "Third streaming message",
];

for (const msg of messages) {
  const pt = new TextEncoder().encode(msg);

  // Sender encrypts
  const ct = contextSeal(senderContext, aad, pt);

  // Receiver decrypts
  const dt = contextOpen(receiverContext, aad, ct);

  console.log("Sent/Received:", new TextDecoder().decode(dt));
}

console.log("\nSequence numbers after streaming:");
console.log("Sender:", senderContext.sequenceNumber);
console.log("Receiver:", receiverContext.sequenceNumber);

// Example 3: Context export for key derivation
console.log("\n--- Context Export ---");

const exportContext = new TextEncoder().encode("mls key derivation");
const exportedKey = contextExport(senderContext, exportContext, 32);

console.log("Exported key length:", exportedKey.length);
console.log(
  "Exported key (hex):",
  Array.from(exportedKey)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(""),
);

// Both sender and receiver derive the same key
const receiverExportedKey = contextExport(receiverContext, exportContext, 32);
console.log(
  "Keys match:",
  exportedKey.every((b, i) => b === receiverExportedKey[i]),
);

console.log("\n=== HPKE Example Complete ===");
