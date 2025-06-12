import { RatchetTree } from "./src/ratchet-tree.ts";

// Test current implementation
console.log("Current implementation:");
console.log("sibling(0):", RatchetTree.sibling(0));
console.log("sibling(2):", RatchetTree.sibling(2));

console.log("\nTesting levels:");
console.log("level(0):", RatchetTree.level(0));
console.log("level(1):", RatchetTree.level(1));
console.log("level(2):", RatchetTree.level(2));
console.log("level(7):", RatchetTree.level(7));

console.log("\nTesting parent/child relationships:");
console.log("parent(0):", RatchetTree.parent(0));
console.log("parent(2):", RatchetTree.parent(2));
console.log("leftChild(1):", RatchetTree.leftChild(1));
console.log("rightChild(1):", RatchetTree.rightChild(1));
