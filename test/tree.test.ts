/**
 * MLS Tree Operations tests
 */

import {
  assertEquals,
  assertExists,
  assertNotEquals,
} from "https://deno.land/std@0.210.0/assert/mod.ts";
import {
  CipherSuite,
  LeafNodeSource,
  ProtocolVersion,
  ResumptionPSKUsage,
  WireFormat,
} from "../src/types.ts";
import { createGroup, resumeGroup } from "../src/group.ts";
import { createMLSClient } from "../src/client.ts";
import { InMemoryMLSStorage } from "../src/storage-memory.ts";
import { RatchetTree } from "../src/ratchet-tree.ts";
import { generateRandom } from "../src/crypto.ts";

Deno.test("RatchetTree - Basic operations", () => {
  // Initialize a tree
  const tree = new RatchetTree(
    CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
  );
  assertEquals(tree.leafCount, 0);
  assertEquals(tree.depth, 0);

  // Test leaf to node conversion (even indices for leaves in RFC 9420)
  const leafIndex1 = 0;
  const nodeIndex1 = RatchetTree.leafToNode(leafIndex1);
  assertEquals(nodeIndex1, 0); // 2*0 = 0

  const leafIndex2 = 5;
  const nodeIndex2 = RatchetTree.leafToNode(leafIndex2);
  assertEquals(nodeIndex2, 10); // 2*5 = 10

  // Test node to leaf conversion
  assertEquals(RatchetTree.nodeToLeaf(nodeIndex1), leafIndex1);
  assertEquals(RatchetTree.nodeToLeaf(nodeIndex2), leafIndex2);

  // Test parent/child relationships with RFC 9420 indexing
  // In a 4-leaf tree: leaves at 0,2,4,6 and parents at 1,3,5 with root at 3
  // Tree structure:    3
  //                   / \
  //                  1   5
  //                 / \ / \
  //                0  2 4  6
  assertEquals(RatchetTree.parent(0), 1); // Parent of leaf 0 is 1
  assertEquals(RatchetTree.parent(2), 1); // Parent of leaf 2 is 1 (RFC test vectors)
  assertEquals(RatchetTree.leftChild(1), 0); // Left child of 1 is 0
  assertEquals(RatchetTree.rightChild(1), 2); // Right child of 1 is 2
  assertEquals(RatchetTree.sibling(0), 2); // Sibling of 0 is 2
  assertEquals(RatchetTree.sibling(2), 0); // Sibling of 2 is 0

  // Test level calculation
  assertEquals(RatchetTree.level(0), 0); // Even indices are leaves (level 0)
  assertEquals(RatchetTree.level(2), 0); // Even indices are leaves (level 0)
  assertEquals(RatchetTree.level(1), 1); // Odd indices are parents (level 1+)
  assertEquals(RatchetTree.level(7), 3); // Higher level parent
});

Deno.test("RatchetTree - Path computation", () => {
  // Create a simple tree with 4 nodes
  const tree = new RatchetTree(
    CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
  );

  // Add leaf nodes (just stubs for testing)
  const leaf = {
    encryptionKey: new Uint8Array(32),
    signatureKey: new Uint8Array(32),
    credential: {
      credentialType: 1,
      identity: new TextEncoder().encode("test"),
    },
    capabilities: {
      versions: [ProtocolVersion.MLS10],
      cipherSuites: [CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
      extensions: [],
      proposals: [],
      credentials: [],
    },
    leafNodeSource: LeafNodeSource.KEY_PACKAGE,
    lifetime: {
      notBefore: 0n,
      notAfter: BigInt(Date.now() + 24 * 60 * 60 * 1000),
    }, // 24 hours validity
    extensions: [],
    signature: new Uint8Array(64),
  };

  tree.addLeaf(leaf);
  tree.addLeaf(leaf);
  tree.addLeaf(leaf);
  tree.addLeaf(leaf);

  // With 4 leaves, we have a tree of depth 2
  assertEquals(tree.leafCount, 4);
  assertEquals(tree.depth, 2);

  // Test directPath - path from leaf to root
  const directPath0 = tree.directPath(0);
  assertEquals(directPath0.length, 2); // Two parents from leaf 0 to root
  assertEquals(directPath0[0], 1);
  assertEquals(directPath0[1], 3); // Root is at 3 for 4 leaves (RFC test vectors)

  const directPath1 = tree.directPath(1);
  assertEquals(directPath1.length, 2); // Two parents from leaf 1 to root
  assertEquals(directPath1[0], 1);
  assertEquals(directPath1[1], 3);

  // Test copath - siblings along the path
  const copath0 = tree.copath(0);
  assertEquals(copath0.length, 2);
  assertEquals(copath0[0], 2); // Sibling of leaf 0 (node 0) is node 2
  assertEquals(copath0[1], 5); // Sibling of parent 1 is parent 5

  const copath1 = tree.copath(1);
  assertEquals(copath1.length, 2);
  assertEquals(copath1[0], 0); // Sibling of leaf 1 (node 2) is node 0
  assertEquals(copath1[1], 5); // Sibling of parent 1 is parent 5
});

Deno.test("RatchetTree - Tree hash", () => {
  // Create a tree and verify tree hash changes when tree structure changes
  const tree = new RatchetTree(
    CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
  );

  const leaf = {
    encryptionKey: generateRandom(32),
    signatureKey: generateRandom(32),
    credential: {
      credentialType: 1,
      identity: new TextEncoder().encode("test"),
    },
    capabilities: {
      versions: [ProtocolVersion.MLS10],
      cipherSuites: [CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
      extensions: [],
      proposals: [],
      credentials: [],
    },
    leafNodeSource: LeafNodeSource.KEY_PACKAGE,
    lifetime: {
      notBefore: 0n,
      notAfter: BigInt(Date.now() + 24 * 60 * 60 * 1000),
    }, // Add lifetime
    extensions: [],
    signature: generateRandom(64),
  };

  // Compute initial hash
  const hash0 = tree.treeHash();

  // Add a leaf
  tree.addLeaf(leaf);
  const hash1 = tree.treeHash();

  // Hashes should be different
  assertNotEquals(hash0, hash1);

  // Add another leaf
  tree.addLeaf(leaf);
  const hash2 = tree.treeHash();

  // Hash should change again
  assertNotEquals(hash1, hash2);
  assertNotEquals(hash0, hash2);

  // Remove a leaf
  tree.removeLeaf(1);
  const hash3 = tree.treeHash();

  // Hash should change after removal
  assertNotEquals(hash2, hash3);
});

Deno.test("MLSGroup - Group resumption", async () => {
  const storage = new InMemoryMLSStorage();
  const groupId = generateRandom(32);
  const newGroupId = generateRandom(32);
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

  // Create Charlie's client and key package
  const charlieClient = await createMLSClient(
    "charlie@example.com",
    new InMemoryMLSStorage(),
  );
  const charlieKeyPackage = await charlieClient.generateKeyPackage(suite);

  // Alice adds Bob and Charlie
  await aliceGroup.addMember(bobKeyPackage);
  await aliceGroup.addMember(charlieKeyPackage);
  await aliceGroup.commit();

  assertEquals(aliceGroup.getMembers().length, 3);
  assertEquals(aliceGroup.getEpoch(), 1n); // 1 commit = epoch 1

  // Create a resumed group with Alice and Charlie but not Bob
  const resumedGroup = await resumeGroup(
    aliceGroup,
    newGroupId,
    [0, 2], // Alice and Charlie
    ResumptionPSKUsage.APPLICATION,
    storage,
  );

  // Verify resumed group properties
  assertExists(resumedGroup);
  assertEquals(resumedGroup.getMembers().length, 2); // Only Alice and Charlie
  assertEquals(resumedGroup.getEpoch(), 1n); // 1 commit = epoch 1

  // Group IDs should be different
  assertNotEquals(
    new TextDecoder().decode(resumedGroup.getGroupId()),
    new TextDecoder().decode(aliceGroup.getGroupId()),
  );

  // Send a message in the resumed group
  const message = new TextEncoder().encode("Hello resumed group");
  const encryptedMessage = await resumedGroup.encryptMessage(message);

  assertExists(encryptedMessage);
  assertEquals(encryptedMessage.wireFormat, WireFormat.PrivateMessage);

  // Decrypt the message
  const decrypted = await resumedGroup.decryptMessage(encryptedMessage);
  assertEquals(new TextDecoder().decode(decrypted), "Hello resumed group");
});
