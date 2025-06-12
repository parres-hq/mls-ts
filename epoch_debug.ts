console.log("Testing epoch count issue...");

import { createGroup } from "./src/group.ts";
import { createMLSClient } from "./src/client.ts";
import { InMemoryMLSStorage } from "./src/storage-memory.ts";
import { CipherSuite } from "./src/types.ts";
import { generateRandom } from "./src/crypto.ts";

const storage = new InMemoryMLSStorage();
const groupId = generateRandom(32);
const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

// Create group
const aliceIdentity = new TextEncoder().encode("alice@example.com");
const aliceGroup = await createGroup(groupId, suite, aliceIdentity, storage);
console.log("After create group, epoch:", aliceGroup.getEpoch());

// Create Bob's client
const bobClient = await createMLSClient(
  "bob@example.com",
  new InMemoryMLSStorage(),
);
const bobKeyPackage = await bobClient.generateKeyPackage(suite);

// Add Bob
const proposalRef = aliceGroup.addMember(bobKeyPackage);
console.log("After addMember, epoch:", aliceGroup.getEpoch());

// Commit
const result = await aliceGroup.commit();
console.log("After commit, epoch:", aliceGroup.getEpoch());
console.log("Expected: 1, Actual:", aliceGroup.getEpoch());
