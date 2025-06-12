/**
 * MLS Group operations tests
 */

import {
  assertEquals,
  assertExists,
} from "https://deno.land/std@0.210.0/assert/mod.ts";
import { CipherSuite, ProtocolVersion, WireFormat } from "../src/types.ts";
import { createGroup } from "../src/group.ts";
import { createMLSClient } from "../src/client.ts";
import { InMemoryMLSStorage } from "../src/storage-memory.ts";
import { generateRandom } from "../src/crypto.ts";

Deno.test("MLSGroup - Create group", async () => {
  const storage = new InMemoryMLSStorage();
  const groupId = generateRandom(32);
  const identity = new TextEncoder().encode("alice@example.com");

  const group = await createGroup(
    groupId,
    CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    identity,
    storage,
  );

  assertExists(group);
  assertEquals(group.getEpoch(), 0n);
  assertEquals(group.getGroupId(), groupId);

  const members = group.getMembers();
  assertEquals(members.length, 1);
  assertEquals(members[0].credential.identity, identity);
});

Deno.test("MLSGroup - Add member", async () => {
  const storage = new InMemoryMLSStorage();
  const groupId = generateRandom(32);
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

  // Create group with Alice
  const aliceIdentity = new TextEncoder().encode("alice@example.com");
  const aliceGroup = await createGroup(groupId, suite, aliceIdentity, storage);

  // Create Bob's client and key package
  const bobClient = await createMLSClient(
    "bob@example.com",
    new InMemoryMLSStorage(),
  );
  const bobKeyPackage = await bobClient.generateKeyPackage(suite);

  // Alice adds Bob
  const proposalRef = await aliceGroup.addMember(bobKeyPackage);
  assertExists(proposalRef);

  // Alice commits
  const { commit, welcome } = await aliceGroup.commit();
  assertExists(commit);
  assertExists(welcome);

  // Check epoch incremented correctly
  assertEquals(aliceGroup.getEpoch(), 1n);

  // Check members
  const members = aliceGroup.getMembers();
  assertEquals(members.length, 2);
});

Deno.test("MLSGroup - Remove member", async () => {
  const storage = new InMemoryMLSStorage();
  const groupId = generateRandom(32);
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

  // Create group and add members
  const aliceGroup = await createGroup(
    groupId,
    suite,
    new TextEncoder().encode("alice@example.com"),
    storage,
  );

  const bobClient = await createMLSClient(
    "bob@example.com",
    new InMemoryMLSStorage(),
  );
  const bobKeyPackage = await bobClient.generateKeyPackage(suite);

  await aliceGroup.addMember(bobKeyPackage);
  await aliceGroup.commit();

  // Remove Bob (index 1)
  const removeRef = await aliceGroup.removeMember(1);
  assertExists(removeRef);

  const { commit } = await aliceGroup.commit();
  assertExists(commit);

  // Check members
  const members = aliceGroup.getMembers();
  assertEquals(members.length, 1);
  assertEquals(aliceGroup.getEpoch(), 2n); // 2 commits = epoch 2
});

Deno.test("MLSGroup - Update own key", async () => {
  const storage = new InMemoryMLSStorage();
  const groupId = generateRandom(32);
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

  const group = await createGroup(
    groupId,
    suite,
    new TextEncoder().encode("alice@example.com"),
    storage,
  );

  // Get current encryption key
  const membersBefore = group.getMembers();
  const keyBefore = membersBefore[0].encryptionKey;

  // Update
  const updateRef = await group.update();
  assertExists(updateRef);

  const { commit } = await group.commit();
  assertExists(commit);

  // Check key changed
  const membersAfter = group.getMembers();
  const keyAfter = membersAfter[0].encryptionKey;

  assertEquals(keyBefore.length, keyAfter.length);
  // Keys should be different
  let different = false;
  for (let i = 0; i < keyBefore.length; i++) {
    if (keyBefore[i] !== keyAfter[i]) {
      different = true;
      break;
    }
  }
  assertEquals(different, true);
});

Deno.test("MLSGroup - Encrypt and decrypt message", async () => {
  const storage = new InMemoryMLSStorage();
  const groupId = generateRandom(32);
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

  const group = await createGroup(
    groupId,
    suite,
    new TextEncoder().encode("alice@example.com"),
    storage,
  );

  // Encrypt a message
  const plaintext = new TextEncoder().encode("Hello, MLS Group!");
  const ciphertext = await group.encryptMessage(plaintext);

  assertExists(ciphertext);
  assertEquals(ciphertext.protocolVersion, ProtocolVersion.MLS10);
  assertEquals(ciphertext.wireFormat, WireFormat.PrivateMessage);

  // Decrypt the message
  const decrypted = await group.decryptMessage(ciphertext);
  assertEquals(decrypted, plaintext);
});

Deno.test("MLSGroup - Multiple operations in sequence", async () => {
  const storage = new InMemoryMLSStorage();
  const groupId = generateRandom(32);
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

  // Create group
  const group = await createGroup(
    groupId,
    suite,
    new TextEncoder().encode("alice@example.com"),
    storage,
  );

  // Add two members
  const bobClient = await createMLSClient(
    "bob@example.com",
    new InMemoryMLSStorage(),
  );
  const bobKP = await bobClient.generateKeyPackage(suite);

  const charlieClient = await createMLSClient(
    "charlie@example.com",
    new InMemoryMLSStorage(),
  );
  const charlieKP = await charlieClient.generateKeyPackage(suite);

  const bobRef = await group.addMember(bobKP);
  const charlieRef = await group.addMember(charlieKP);

  // Commit both additions at once
  const { commit: addCommit, welcome } = await group.commit([
    bobRef,
    charlieRef,
  ]);
  assertExists(addCommit);
  assertExists(welcome);

  assertEquals(group.getMembers().length, 3);
  assertEquals(group.getEpoch(), 1n); // 1 commit = epoch 1

  // Update own key
  await group.update();
  const { commit: updateCommit } = await group.commit();
  assertExists(updateCommit);

  assertEquals(group.getEpoch(), 2n); // 2 commits = epoch 2

  // Send a message
  const msg1 = await group.encryptMessage(
    new TextEncoder().encode("First message"),
  );
  const decrypted1 = await group.decryptMessage(msg1);
  assertEquals(
    new TextDecoder().decode(decrypted1),
    "First message",
  );

  // Remove Charlie
  await group.removeMember(2);
  const { commit: removeCommit } = await group.commit();
  assertExists(removeCommit);

  assertEquals(group.getMembers().length, 2);
  assertEquals(group.getEpoch(), 3n); // 3 commits = epoch 3

  // Send another message
  const msg2 = await group.encryptMessage(
    new TextEncoder().encode("After removal"),
  );
  const decrypted2 = await group.decryptMessage(msg2);
  assertEquals(
    new TextDecoder().decode(decrypted2),
    "After removal",
  );
});

Deno.test("MLSGroup - Batch proposals", async () => {
  const storage = new InMemoryMLSStorage();
  const groupId = generateRandom(32);
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

  const group = await createGroup(
    groupId,
    suite,
    new TextEncoder().encode("alice@example.com"),
    storage,
  );

  // Create multiple proposals
  const bobClient = await createMLSClient(
    "bob@example.com",
    new InMemoryMLSStorage(),
  );
  const bobKP = await bobClient.generateKeyPackage(suite);

  const charlieClient = await createMLSClient(
    "charlie@example.com",
    new InMemoryMLSStorage(),
  );
  const charlieKP = await charlieClient.generateKeyPackage(suite);

  // Add proposals without committing
  const ref1 = await group.addMember(bobKP);
  const ref2 = await group.addMember(charlieKP);
  const ref3 = await group.update();

  // Commit all at once
  const { commit, welcome } = await group.commit([ref1, ref2, ref3]);
  assertExists(commit);
  assertExists(welcome);

  // Verify state
  assertEquals(group.getEpoch(), 1n); // 1 commit = epoch 1
  assertEquals(group.getMembers().length, 3);
});

Deno.test("MLSGroup - Message ordering", async () => {
  const storage = new InMemoryMLSStorage();
  const groupId = generateRandom(32);
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

  const group = await createGroup(
    groupId,
    suite,
    new TextEncoder().encode("alice@example.com"),
    storage,
  );

  // Send multiple messages
  const messages = [
    "First message",
    "Second message",
    "Third message",
    "Fourth message",
    "Fifth message",
  ];

  const ciphertexts = [];
  for (const msg of messages) {
    const ct = await group.encryptMessage(new TextEncoder().encode(msg));
    ciphertexts.push(ct);
  }

  // Decrypt in order
  for (let i = 0; i < messages.length; i++) {
    const plaintext = await group.decryptMessage(ciphertexts[i]);
    assertEquals(new TextDecoder().decode(plaintext), messages[i]);
  }
});
