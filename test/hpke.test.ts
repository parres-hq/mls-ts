/**
 * HPKE (RFC 9180) implementation tests
 */

import {
  assertEquals,
  assertThrows,
} from "https://deno.land/std@0.210.0/assert/mod.ts";
import { CipherSuite } from "../src/types.ts";
import { generateHPKEKeyPair, generateRandom } from "../src/crypto.ts";
import {
  contextExport,
  contextOpen,
  contextSeal,
  open,
  seal,
  setupBaseR,
  setupBaseS,
  setupPSKR,
  setupPSKS,
} from "../src/hpke.ts";

Deno.test("HPKE basic round-trip encryption", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

  // Generate receiver key pair
  const receiverKeyPair = generateHPKEKeyPair(suite);

  // Info and AAD
  const info = new TextEncoder().encode("test info");
  const aad = new TextEncoder().encode("test aad");

  // Message to encrypt
  const plaintext = new TextEncoder().encode("Hello, HPKE!");

  // Single-shot encryption
  const encrypted = seal(
    suite,
    receiverKeyPair.publicKey,
    info,
    aad,
    plaintext,
  );

  // Single-shot decryption
  const decrypted = open(
    suite,
    encrypted.encappedKey,
    receiverKeyPair.privateKey,
    receiverKeyPair.publicKey,
    info,
    aad,
    encrypted.ciphertext,
  );

  assertEquals(decrypted, plaintext);
});

Deno.test("HPKE streaming encryption", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

  // Generate receiver key pair
  const receiverKeyPair = generateHPKEKeyPair(suite);

  const info = new TextEncoder().encode("streaming test");
  const aad = new TextEncoder().encode("aad");

  // Setup sender
  const { encappedKey, context: senderContext } = setupBaseS(
    suite,
    receiverKeyPair.publicKey,
    info,
  );

  // Setup receiver
  const receiverContext = setupBaseR(
    suite,
    encappedKey,
    receiverKeyPair.privateKey,
    receiverKeyPair.publicKey,
    info,
  );

  // Encrypt multiple messages
  const messages = [
    "First message",
    "Second message",
    "Third message",
  ];

  for (const msg of messages) {
    const plaintext = new TextEncoder().encode(msg);
    const ciphertext = contextSeal(senderContext, aad, plaintext);
    const decrypted = contextOpen(receiverContext, aad, ciphertext);

    assertEquals(decrypted, plaintext);
  }

  // Verify sequence numbers match
  assertEquals(senderContext.sequenceNumber, receiverContext.sequenceNumber);
  assertEquals(senderContext.sequenceNumber, BigInt(messages.length));
});

Deno.test("HPKE with different cipher suites", () => {
  const testSuites = [
    CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    CipherSuite.MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
    CipherSuite.MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
  ];

  for (const suite of testSuites) {
    const keyPair = generateHPKEKeyPair(suite);
    const info = new Uint8Array(0);
    const aad = new Uint8Array(0);
    const plaintext = generateRandom(32);

    const encrypted = seal(suite, keyPair.publicKey, info, aad, plaintext);
    const decrypted = open(
      suite,
      encrypted.encappedKey,
      keyPair.privateKey,
      keyPair.publicKey,
      info,
      aad,
      encrypted.ciphertext,
    );

    assertEquals(decrypted, plaintext);
  }
});

Deno.test("HPKE export functionality", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const keyPair = generateHPKEKeyPair(suite);
  const info = new TextEncoder().encode("export test");

  // Setup contexts
  const { encappedKey, context: senderContext } = setupBaseS(
    suite,
    keyPair.publicKey,
    info,
  );

  const receiverContext = setupBaseR(
    suite,
    encappedKey,
    keyPair.privateKey,
    keyPair.publicKey,
    info,
  );

  // Export secrets with different contexts
  const exportContext1 = new TextEncoder().encode("context 1");
  const exportContext2 = new TextEncoder().encode("context 2");

  const senderExport1 = contextExport(senderContext, exportContext1, 32);
  const receiverExport1 = contextExport(receiverContext, exportContext1, 32);

  const senderExport2 = contextExport(senderContext, exportContext2, 32);
  const receiverExport2 = contextExport(receiverContext, exportContext2, 32);

  // Same context should produce same export
  assertEquals(senderExport1, receiverExport1);
  assertEquals(senderExport2, receiverExport2);

  // Different contexts should produce different exports
  assertThrows(() => assertEquals(senderExport1, senderExport2));
});

Deno.test("HPKE PSK mode", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const keyPair = generateHPKEKeyPair(suite);

  const info = new TextEncoder().encode("psk test");
  const psk = generateRandom(32);
  const pskId = new TextEncoder().encode("test psk id");
  const aad = new TextEncoder().encode("aad");
  const plaintext = new TextEncoder().encode("PSK mode test message");

  // Setup with PSK
  const { encappedKey, context: senderContext } = setupPSKS(
    suite,
    keyPair.publicKey,
    info,
    psk,
    pskId,
  );

  const receiverContext = setupPSKR(
    suite,
    encappedKey,
    keyPair.privateKey,
    keyPair.publicKey,
    info,
    psk,
    pskId,
  );

  // Encrypt and decrypt
  const ciphertext = contextSeal(senderContext, aad, plaintext);
  const decrypted = contextOpen(receiverContext, aad, ciphertext);

  assertEquals(decrypted, plaintext);

  // Wrong PSK should fail
  const wrongPsk = generateRandom(32);
  const wrongContext = setupPSKR(
    suite,
    encappedKey,
    keyPair.privateKey,
    keyPair.publicKey,
    info,
    wrongPsk,
    pskId,
  );

  // This would produce different keys, so decryption would fail
  assertThrows(() => {
    contextOpen(wrongContext, aad, ciphertext);
  });
});

Deno.test("HPKE nonce overflow protection", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const keyPair = generateHPKEKeyPair(suite);
  const info = new Uint8Array(0);
  const aad = new Uint8Array(0);

  const { context } = setupBaseS(suite, keyPair.publicKey, info);

  // Set sequence number close to overflow
  context.sequenceNumber = (1n << 64n) - 1n;

  // This should work
  const plaintext = new TextEncoder().encode("Last message");
  contextSeal(context, aad, plaintext);

  // Next encryption should fail due to overflow
  assertThrows(
    () => contextSeal(context, aad, plaintext),
    Error,
    "sequence number overflow",
  );
});

Deno.test("HPKE ciphertext integrity", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const keyPair = generateHPKEKeyPair(suite);
  const info = new Uint8Array(0);
  const aad = new TextEncoder().encode("integrity test");
  const plaintext = new TextEncoder().encode("Secret message");

  const encrypted = seal(suite, keyPair.publicKey, info, aad, plaintext);

  // Modify ciphertext
  encrypted.ciphertext[0] ^= 0xFF;

  // Decryption should fail
  assertThrows(() => {
    open(
      suite,
      encrypted.encappedKey,
      keyPair.privateKey,
      keyPair.publicKey,
      info,
      aad,
      encrypted.ciphertext,
    );
  });

  // Restore and modify AAD
  encrypted.ciphertext[0] ^= 0xFF;
  const wrongAad = new TextEncoder().encode("wrong aad");

  // Should also fail
  assertThrows(() => {
    open(
      suite,
      encrypted.encappedKey,
      keyPair.privateKey,
      keyPair.publicKey,
      info,
      wrongAad,
      encrypted.ciphertext,
    );
  });
});

Deno.test("HPKE encapsulated key validation", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const keyPair = generateHPKEKeyPair(suite);
  const info = new Uint8Array(0);
  const aad = new Uint8Array(0);
  const plaintext = new TextEncoder().encode("Test");

  const encrypted = seal(suite, keyPair.publicKey, info, aad, plaintext);

  // Use wrong encapsulated key
  const wrongEncappedKey = generateRandom(encrypted.encappedKey.length);

  // Should produce wrong shared secret and fail decryption
  assertThrows(() => {
    open(
      suite,
      wrongEncappedKey,
      keyPair.privateKey,
      keyPair.publicKey,
      info,
      aad,
      encrypted.ciphertext,
    );
  });
});

Deno.test("HPKE export determinism", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const keyPair = generateHPKEKeyPair(suite);
  const info = new TextEncoder().encode("determinism test");

  // Create two identical setups
  const { encappedKey: enc1, context: ctx1 } = setupBaseS(
    suite,
    keyPair.publicKey,
    info,
  );
  const ctx2 = setupBaseR(
    suite,
    enc1,
    keyPair.privateKey,
    keyPair.publicKey,
    info,
  );

  // Export with same parameters should give same results
  const exportCtx = new TextEncoder().encode("export");
  const export1a = contextExport(ctx1, exportCtx, 64);
  const export1b = contextExport(ctx1, exportCtx, 64);
  const export2a = contextExport(ctx2, exportCtx, 64);
  const export2b = contextExport(ctx2, exportCtx, 64);

  assertEquals(export1a, export1b);
  assertEquals(export2a, export2b);
  assertEquals(export1a, export2a);

  // Different lengths should give different results
  const export32 = contextExport(ctx1, exportCtx, 32);
  const export64 = contextExport(ctx1, exportCtx, 64);

  // First 32 bytes should match
  assertEquals(export32, export64.slice(0, 32));
});
