import { assertEquals } from "https://deno.land/std@0.208.0/assert/mod.ts";
import { CipherSuite } from "../src/types.ts";
import {
  generateHPKEKeyPair,
  generateSignatureKeyPair,
  hash,
  sign,
  verify,
} from "../src/crypto.ts";
import { RatchetTree } from "../src/ratchet-tree.ts";
import { KeySchedule } from "../src/key-schedule.ts";

Deno.test("Crypto - Generate HPKE key pair", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const keyPair = generateHPKEKeyPair(suite);

  assertEquals(keyPair.privateKey.length, 32);
  assertEquals(keyPair.publicKey.length, 32);
});

Deno.test("Crypto - Generate signature key pair", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const keyPair = generateSignatureKeyPair(suite);

  assertEquals(keyPair.privateKey.length, 32);
  assertEquals(keyPair.publicKey.length, 32);
});

Deno.test("Crypto - Sign and verify", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const keyPair = generateSignatureKeyPair(suite);
  const message = new TextEncoder().encode("Hello MLS!");

  const signature = sign(suite, keyPair.privateKey, message);
  const valid = verify(suite, keyPair.publicKey, message, signature);

  assertEquals(valid, true);
});

Deno.test("Crypto - Hash", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const data = new TextEncoder().encode("Hello MLS!");

  const hashed = hash(suite, data);
  assertEquals(hashed.length, 32); // SHA256
});

Deno.test("Ratchet Tree - Basic operations", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const tree = new RatchetTree(suite);

  assertEquals(tree.leafCount, 0); // Empty tree has 0 leaves
  assertEquals(tree.depth, 0);

  // Add a leaf
  const leaf = {
    encryptionKey: new Uint8Array(32),
    signatureKey: new Uint8Array(32),
    credential: { credentialType: 1, identity: new Uint8Array(0) },
    capabilities: {
      versions: [1],
      cipherSuites: [suite],
      extensions: [],
      proposals: [],
      credentials: [1],
    },
    leafNodeSource: 1,
    lifetime: { notBefore: 0n, notAfter: 0n },
    extensions: [],
    signature: new Uint8Array(64),
  };

  const leafIndex = tree.addLeaf(leaf);
  assertEquals(leafIndex, 0);
  assertEquals(tree.leafCount, 1);
});

Deno.test("Key Schedule - Initialize epoch 0", () => {
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const groupContext = {
    protocolVersion: 1,
    cipherSuite: suite,
    groupId: new Uint8Array(32),
    epoch: 0n,
    treeHash: new Uint8Array(32),
    confirmedTranscriptHash: new Uint8Array(0),
    extensions: [],
  };

  const keySchedule = new KeySchedule(suite, groupContext);
  const secrets = keySchedule.initEpoch0();

  assertEquals(secrets.initSecret.length, 32);
  assertEquals(secrets.encryptionSecret.length, 32);
  assertEquals(secrets.confirmationKey.length, 32);
});

Deno.test("Storage - Basic operations", () => {
  // Skip storage test for now since IndexedDB is not available in Deno test environment
  // In production, this would run in a browser or with a polyfill
  console.log(
    "Skipping storage test - IndexedDB not available in test environment",
  );
});
