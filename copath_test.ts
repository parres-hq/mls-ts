
import { RatchetTree } from './src/ratchet-tree.ts';

console.log('Testing copath calculation:');
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

tree.addLeaf(leaf); // leaf 0 -> node 0
tree.addLeaf(leaf); // leaf 1 -> node 2  
tree.addLeaf(leaf); // leaf 2 -> node 4
tree.addLeaf(leaf); // leaf 3 -> node 6

console.log('Tree structure for 4 leaves:');
console.log('Leaves: 0,2,4,6  Parents: 1,3,5  Root: 3');
console.log('Tree:      3');
console.log('         /   \\');
console.log('        1     5');  
console.log('       / \\   / \\');
console.log('      0   2 4   6');

console.log('\nDirectPaths:');
console.log('leaf 0 (node 0) directPath:', tree.directPath(0));
console.log('leaf 1 (node 2) directPath:', tree.directPath(1));

console.log('\nCopaths:');  
console.log('leaf 0 (node 0) copath:', tree.copath(0));
console.log('leaf 1 (node 2) copath:', tree.copath(1));

console.log('\nSiblings:');
console.log('sibling(0):', RatchetTree.sibling(0)); // leaf 0 
console.log('sibling(2):', RatchetTree.sibling(2)); // leaf 1
console.log('sibling(1):', RatchetTree.sibling(1)); // parent 1
console.log('sibling(5):', RatchetTree.sibling(5)); // parent 5

