
// For 4 leaves (0,1,2,3) -> nodes (0,2,4,6)
// RFC test vectors for 4 leaves: parent array [1, 3, 1, null, 5, 3, 5]
// This means:
// node 0 (leaf 0): parent = 1
// node 2 (leaf 1): parent = 1  
// node 4 (leaf 2): parent = 5
// node 6 (leaf 3): parent = 5
// parent 1: parent = 3
// parent 5: parent = 3
// parent 3: parent = null (root)

import { RatchetTree } from './src/ratchet-tree.ts';

console.log('Testing with 4 leaves (leaf indices 0,1,2,3 -> node indices 0,2,4,6):');
console.log('leaf 0 (node 0) directPath should be: [1,3]');
console.log('leaf 1 (node 2) directPath should be: [1,3]'); 
console.log('leaf 2 (node 4) directPath should be: [5,3]');
console.log('leaf 3 (node 6) directPath should be: [5,3]');

// Create tree and test
const tree = new RatchetTree(1); // CipherSuite enum value
const leaf = {
  encryptionKey: new Uint8Array(32),
  signatureKey: new Uint8Array(32),
  credential: { credentialType: 1, identity: new Uint8Array(4) },
  capabilities: { versions: [1], cipherSuites: [1], extensions: [], proposals: [], credentials: [] },
  leafNodeSource: 1,
  lifetime: { notBefore: 0n, notAfter: 1000000n },
  extensions: [],
  signature: new Uint8Array(32)
};

tree.addLeaf(leaf);
tree.addLeaf(leaf);
tree.addLeaf(leaf);
tree.addLeaf(leaf);

console.log('\nActual results:');
console.log('leaf 0 directPath:', tree.directPath(0));
console.log('leaf 1 directPath:', tree.directPath(1));
console.log('leaf 0 copath:', tree.copath(0));
console.log('leaf 1 copath:', tree.copath(1));
console.log('root index:', tree.rootIndex());

