import { RatchetTree } from "./src/ratchet-tree.ts";

console.log("parent(0):", RatchetTree.parent(0), "(expected: 1)");
console.log("parent(2):", RatchetTree.parent(2), "(expected: 3)");
console.log("parent(4):", RatchetTree.parent(4), "(expected: 5)");
console.log("parent(6):", RatchetTree.parent(6), "(expected: 5)");
