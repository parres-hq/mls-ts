import { RatchetTree } from "./src/ratchet-tree.ts";

console.log("Testing new root index calculation:");
const tree = new RatchetTree(1); // CipherSuite enum value
const leaf = {
  encryptionKey: new Uint8Array(32),
  signatureKey: new Uint8Array(32),
  credential: { credentialType: 1, identity: new Uint8Array(4) },
  capabilities: {
    versions: [1],
    cipherSuites: [1],
    extensions: [],
    proposals: [],
    credentials: [],
  },
  leafNodeSource: 1,
  lifetime: { notBefore: 0n, notAfter: 1000000n },
  extensions: [],
  signature: new Uint8Array(32),
};

for (let i = 1; i <= 8; i++) {
  tree.addLeaf(leaf);
  console.log(`${i} leaves: root = ${tree.rootIndex()}`);
}
