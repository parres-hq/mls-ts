/**
 * Ratchet tree implementation for MLS
 * Based on RFC 9420 Section 4 and Section 7
 */

import type {
  HPKEPrivateKey,
  HPKEPublicKey,
  LeafIndex,
  LeafNode,
  NodeIndex,
  ParentNode,
  RatchetNode,
  UpdatePath,
} from "./types.ts";
import { NodeType } from "./types.ts";
import { hash } from "./crypto.ts";
import type { CipherSuite } from "./types.ts";
import { encodeLeafNode, encodeParentNode, Encoder } from "./encoding.ts";

// Re-export types used in the public API
export type { LeafIndex, NodeIndex } from "./types.ts";

/**
 * Ratchet tree implementation
 */
export class RatchetTree {
  private nodes: (RatchetNode | null)[];
  private suite: CipherSuite;

  constructor(suite: CipherSuite, nodes?: (RatchetNode | null)[]) {
    this.suite = suite;
    this.nodes = nodes || [];
  }

  /**
   * Get the number of leaves in the tree
   */
  get leafCount(): number {
    if (this.nodes.length === 0) return 0;
    return Math.ceil((this.nodes.length + 1) / 2);
  }

  /**
   * Get total size (number of leaves) - alias for leafCount
   */
  size(): number {
    return this.leafCount;
  }

  /**
   * Get the depth of the tree
   */
  get depth(): number {
    return Math.ceil(Math.log2(Math.max(1, this.leafCount)));
  }

  /**
   * Get a node by index
   */
  getNode(index: NodeIndex): RatchetNode | null {
    return this.nodes[index] || null;
  }

  /**
   * Get a leaf node by leaf index
   */
  getLeafNode(leafIndex: LeafIndex): LeafNode | null {
    const nodeIndex = RatchetTree.leafToNode(leafIndex);
    const node = this.getNode(nodeIndex);
    if (node && this.isLeaf(nodeIndex)) {
      return node as LeafNode;
    }
    return null;
  }

  /**
   * Set a node by index
   */
  setNode(index: NodeIndex, node: RatchetNode | null): void {
    // Ensure array is large enough
    while (this.nodes.length <= index) {
      this.nodes.push(null);
    }
    this.nodes[index] = node;
  }

  /**
   * Get the parent index of a node
   */
  static parent(index: NodeIndex): NodeIndex {
    if (index === 0) {
      throw new Error("Root node has no parent");
    }
    const level = this.level(index);
    return (index | (1 << level)) + 1;
  }

  /**
   * Get the left child index of a parent node
   */
  static leftChild(index: NodeIndex): NodeIndex {
    const level = this.level(index);
    if (level === 0) {
      throw new Error("Leaf node has no children");
    }
    return index - (1 << (level - 1));
  }

  /**
   * Get the right child index of a parent node
   */
  static rightChild(index: NodeIndex): NodeIndex {
    const level = this.level(index);
    if (level === 0) {
      throw new Error("Leaf node has no children");
    }
    return index + (1 << (level - 1));
  }

  /**
   * Get the sibling index of a node
   */
  static sibling(index: NodeIndex): NodeIndex {
    const parentIdx = this.parent(index);
    const leftIdx = this.leftChild(parentIdx);
    const rightIdx = this.rightChild(parentIdx);
    return index === leftIdx ? rightIdx : leftIdx;
  }

  /**
   * Get the level of a node (0 for leaves)
   */
  static level(index: NodeIndex): number {
    if (index & 1) {
      return 0; // Odd indices are leaves
    }

    let level = 0;
    let idx = index;
    while ((idx & 1) === 0 && idx > 0) {
      level++;
      idx >>= 1;
    }
    return level;
  }

  /**
   * Convert leaf index to node index
   */
  static leafToNode(leafIndex: LeafIndex): NodeIndex {
    return 2 * leafIndex;
  }

  /**
   * Convert node index to leaf index (if it's a leaf)
   */
  static nodeToLeaf(nodeIndex: NodeIndex): LeafIndex {
    if (this.level(nodeIndex) !== 0) {
      throw new Error("Node is not a leaf");
    }
    return nodeIndex >> 1;
  }

  /**
   * Get the direct path from a leaf to the root
   */
  directPath(leafIndex: LeafIndex): NodeIndex[] {
    const path: NodeIndex[] = [];
    let nodeIndex = RatchetTree.leafToNode(leafIndex);

    while (nodeIndex !== this.rootIndex()) {
      nodeIndex = RatchetTree.parent(nodeIndex);
      path.push(nodeIndex);
    }

    return path;
  }

  /**
   * Get the copath of a leaf
   */
  copath(leafIndex: LeafIndex): NodeIndex[] {
    const path: NodeIndex[] = [];
    let nodeIndex = RatchetTree.leafToNode(leafIndex);

    while (nodeIndex !== this.rootIndex()) {
      path.push(RatchetTree.sibling(nodeIndex));
      nodeIndex = RatchetTree.parent(nodeIndex);
    }

    return path;
  }

  /**
   * Get the filtered direct path of a leaf
   */
  filteredDirectPath(leafIndex: LeafIndex): NodeIndex[] {
    const directPath = this.directPath(leafIndex);
    const copath = this.copath(leafIndex);
    const filtered: NodeIndex[] = [];

    for (let i = 0; i < directPath.length; i++) {
      const copathChild = copath[i];
      const resolution = this.resolve(copathChild);

      // Include in filtered path if copath child has non-empty resolution
      if (resolution.length > 0) {
        filtered.push(directPath[i]);
      }
    }

    return filtered;
  }

  /**
   * Get the root index
   */
  rootIndex(): NodeIndex {
    return (1 << this.depth) - 1;
  }

  /**
   * Check if a node is blank
   */
  isBlank(index: NodeIndex): boolean {
    return this.getNode(index) === null;
  }

  /**
   * Check if a node is a leaf
   */
  isLeaf(index: NodeIndex): boolean {
    return RatchetTree.level(index) === 0;
  }

  /**
   * Get the resolution of a node
   */
  resolve(index: NodeIndex): NodeIndex[] {
    const node = this.getNode(index);

    // Non-blank node
    if (node !== null) {
      const resolution = [index];

      // Add unmerged leaves for parent nodes
      if (!this.isLeaf(index) && "unmergedLeaves" in node) {
        const parentNode = node as ParentNode;
        for (const leafIdx of parentNode.unmergedLeaves) {
          resolution.push(RatchetTree.leafToNode(leafIdx));
        }
      }

      return resolution;
    }

    // Blank leaf
    if (this.isLeaf(index)) {
      return [];
    }

    // Blank parent - concatenate resolutions of children
    const left = RatchetTree.leftChild(index);
    const right = RatchetTree.rightChild(index);
    return [...this.resolve(left), ...this.resolve(right)];
  }

  /**
   * Blank a node and its ancestors
   */
  blank(index: NodeIndex): void {
    // Blank the node
    this.setNode(index, null);

    // Blank ancestors
    let current = index;
    while (current !== this.rootIndex()) {
      current = RatchetTree.parent(current);
      this.setNode(current, null);
    }
  }

  /**
   * Merge a leaf (remove it from unmerged leaves of ancestors)
   */
  merge(leafIndex: LeafIndex): void {
    const nodeIndex = RatchetTree.leafToNode(leafIndex);
    let current = nodeIndex;

    while (current !== this.rootIndex()) {
      current = RatchetTree.parent(current);
      const node = this.getNode(current);

      if (node && !this.isLeaf(current) && "unmergedLeaves" in node) {
        const parentNode = node as ParentNode;
        parentNode.unmergedLeaves = parentNode.unmergedLeaves.filter(
          (idx) => idx !== leafIndex,
        );
      }
    }
  }

  /**
   * Add a leaf to the tree
   */
  addLeaf(leaf: LeafNode): LeafIndex {
    const newLeafIndex = this.leafCount;
    const newNodeIndex = RatchetTree.leafToNode(newLeafIndex);

    // Extend tree if necessary
    if (newNodeIndex >= Math.pow(2, this.depth + 1) - 1) {
      this.extend();
    }

    // Set the leaf
    this.setNode(newNodeIndex, leaf);

    // Mark as unmerged in ancestors (if not root)
    let current = newNodeIndex;
    while (current !== this.rootIndex() && current !== 0) {
      current = RatchetTree.parent(current);
      const node = this.getNode(current);

      if (node && !this.isLeaf(current) && "unmergedLeaves" in node) {
        const parentNode = node as ParentNode;
        if (!parentNode.unmergedLeaves.includes(newLeafIndex)) {
          parentNode.unmergedLeaves.push(newLeafIndex);
          // Keep sorted
          parentNode.unmergedLeaves.sort((a, b) => a - b);
        }
      }
    }

    return newLeafIndex;
  }

  /**
   * Remove a leaf from the tree
   */
  removeLeaf(leafIndex: LeafIndex): void {
    const nodeIndex = RatchetTree.leafToNode(leafIndex);

    // Blank the leaf and its ancestors
    this.blank(nodeIndex);

    // Remove from unmerged leaves
    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];
      if (node && !this.isLeaf(i) && "unmergedLeaves" in node) {
        const parentNode = node as ParentNode;
        parentNode.unmergedLeaves = parentNode.unmergedLeaves.filter(
          (idx) => idx !== leafIndex,
        );
      }
    }

    // Truncate if possible
    this.truncate();
  }

  /**
   * Update a leaf in the tree
   */
  updateLeaf(leafIndex: LeafIndex, newLeaf: LeafNode): void {
    const nodeIndex = RatchetTree.leafToNode(leafIndex);
    this.setNode(nodeIndex, newLeaf);
  }

  /**
   * Extend the tree by one level
   */
  private extend(): void {
    const oldRoot = this.rootIndex();
    const newRoot = (oldRoot << 1) + 1;

    // Create new root
    const newRootNode: ParentNode = {
      encryptionKey: new Uint8Array(0), // Will be set later
      parentHash: new Uint8Array(0),
      unmergedLeaves: [],
    };

    // Copy existing tree to left subtree of new root
    const newNodes: (RatchetNode | null)[] = new Array(newRoot + 1).fill(null);

    // Copy existing nodes
    for (let i = 0; i <= oldRoot; i++) {
      newNodes[i] = this.nodes[i];
    }

    // Set new root
    newNodes[newRoot] = newRootNode;

    this.nodes = newNodes;
  }

  /**
   * Truncate the tree if the right subtree is empty
   */
  private truncate(): void {
    while (this.leafCount > 1) {
      const root = this.rootIndex();
      const rightChild = RatchetTree.rightChild(root);

      // Check if right subtree is empty
      if (!this.isSubtreeEmpty(rightChild)) {
        break;
      }

      // Remove the right subtree and make left child the new root
      const leftChild = RatchetTree.leftChild(root);
      const newNodes: (RatchetNode | null)[] = [];

      // Copy only the left subtree
      for (let i = 0; i <= leftChild; i++) {
        newNodes[i] = this.nodes[i];
      }

      this.nodes = newNodes;
    }
  }

  /**
   * Check if a subtree is empty (all nodes are blank)
   */
  private isSubtreeEmpty(index: NodeIndex): boolean {
    if (this.getNode(index) !== null) {
      return false;
    }

    if (this.isLeaf(index)) {
      return true;
    }

    const left = RatchetTree.leftChild(index);
    const right = RatchetTree.rightChild(index);

    return this.isSubtreeEmpty(left) && this.isSubtreeEmpty(right);
  }

  /**
   * Compute the tree hash
   */
  treeHash(): Uint8Array {
    return this.computeTreeHash(this.rootIndex());
  }

  /**
   * Compute tree hash for a node
   * @param index The node index to compute hash for
   */
  computeTreeHash(index: NodeIndex): Uint8Array {
    const encoder = new Encoder();

    if (this.isLeaf(index)) {
      // Leaf node
      encoder.writeUint8(NodeType.LEAF);
      encoder.writeUint32(RatchetTree.nodeToLeaf(index));

      const node = this.getNode(index);
      if (node) {
        encoder.writeUint8(1); // Present
        encoder.writeBytes(encodeLeafNode(node as LeafNode));
      } else {
        encoder.writeUint8(0); // Absent
      }
    } else {
      // Parent node
      encoder.writeUint8(NodeType.PARENT);

      const node = this.getNode(index);
      if (node) {
        encoder.writeUint8(1); // Present
        encoder.writeBytes(encodeParentNode(node as ParentNode));
      } else {
        encoder.writeUint8(0); // Absent
      }

      // Left and right hashes
      const leftHash = this.computeTreeHash(RatchetTree.leftChild(index));
      const rightHash = this.computeTreeHash(RatchetTree.rightChild(index));

      encoder.writeVarintVector(leftHash);
      encoder.writeVarintVector(rightHash);
    }

    return hash(this.suite, encoder.finish());
  }

  /**
   * Compute parent hash for a node
   */
  computeParentHash(index: NodeIndex, copath: NodeIndex): Uint8Array {
    const node = this.getNode(index);
    if (!node) {
      throw new Error("Cannot compute parent hash for blank node");
    }

    const encoder = new Encoder();

    // Encryption key
    encoder.writeVarintVector(node.encryptionKey);

    // Parent hash (empty for root)
    if (index === this.rootIndex()) {
      encoder.writeVarintVector(new Uint8Array(0));
    } else {
      const parentNode = node as ParentNode;
      encoder.writeVarintVector(parentNode.parentHash);
    }

    // Original sibling tree hash
    const siblingHash = this.computeOriginalTreeHash(copath, node);
    encoder.writeVarintVector(siblingHash);

    return hash(this.suite, encoder.finish());
  }

  /**
   * Compute original tree hash for parent hash calculation
   */
  private computeOriginalTreeHash(
    index: NodeIndex,
    parentNode: RatchetNode,
  ): Uint8Array {
    // Clone the subtree and remove unmerged leaves
    const clonedTree = this.cloneSubtree(index);

    if (!this.isLeaf(index) && parentNode && "unmergedLeaves" in parentNode) {
      const parent = parentNode as ParentNode;
      for (const leafIdx of parent.unmergedLeaves) {
        this.blankInSubtree(clonedTree, index, leafIdx);
      }
    }

    return this.computeSubtreeHash(clonedTree, index);
  }

  /**
   * Clone a subtree for hash computation
   */
  private cloneSubtree(root: NodeIndex): Map<NodeIndex, RatchetNode | null> {
    const subtree = new Map<NodeIndex, RatchetNode | null>();

    const visit = (index: NodeIndex) => {
      if (index >= this.nodes.length) return;

      subtree.set(index, this.getNode(index));

      if (!this.isLeaf(index)) {
        visit(RatchetTree.leftChild(index));
        visit(RatchetTree.rightChild(index));
      }
    };

    visit(root);
    return subtree;
  }

  /**
   * Blank a leaf in a subtree clone
   */
  private blankInSubtree(
    subtree: Map<NodeIndex, RatchetNode | null>,
    root: NodeIndex,
    leafIndex: LeafIndex,
  ): void {
    const nodeIndex = RatchetTree.leafToNode(leafIndex);

    // Check if leaf is in subtree
    if (!subtree.has(nodeIndex)) return;

    // Blank the leaf
    subtree.set(nodeIndex, null);

    // Remove from unmerged leaves in subtree
    subtree.forEach((node, idx) => {
      if (node && !this.isLeaf(idx) && "unmergedLeaves" in node) {
        const parent = node as ParentNode;
        parent.unmergedLeaves = parent.unmergedLeaves.filter((i) =>
          i !== leafIndex
        );
      }
    });
  }

  /**
   * Compute hash of a subtree clone
   */
  private computeSubtreeHash(
    subtree: Map<NodeIndex, RatchetNode | null>,
    index: NodeIndex,
  ): Uint8Array {
    const encoder = new Encoder();
    const node = subtree.get(index) || null;

    if (this.isLeaf(index)) {
      encoder.writeUint8(NodeType.LEAF);
      encoder.writeUint32(RatchetTree.nodeToLeaf(index));

      if (node) {
        encoder.writeUint8(1);
        encoder.writeBytes(encodeLeafNode(node as LeafNode));
      } else {
        encoder.writeUint8(0);
      }
    } else {
      encoder.writeUint8(NodeType.PARENT);

      if (node) {
        encoder.writeUint8(1);
        encoder.writeBytes(encodeParentNode(node as ParentNode));
      } else {
        encoder.writeUint8(0);
      }

      const leftHash = this.computeSubtreeHash(
        subtree,
        RatchetTree.leftChild(index),
      );
      const rightHash = this.computeSubtreeHash(
        subtree,
        RatchetTree.rightChild(index),
      );

      encoder.writeVarintVector(leftHash);
      encoder.writeVarintVector(rightHash);
    }

    return hash(this.suite, encoder.finish());
  }

  /**
   * Get all occupied leaf indices
   */
  getOccupiedLeaves(): LeafIndex[] {
    const leaves: LeafIndex[] = [];

    for (let i = 0; i < this.leafCount; i++) {
      const nodeIndex = RatchetTree.leafToNode(i);
      if (this.getNode(nodeIndex) !== null) {
        leaves.push(i);
      }
    }

    return leaves;
  }

  /**
   * Find a free leaf slot
   */
  findFreeLeaf(): LeafIndex | null {
    for (let i = 0; i < this.leafCount; i++) {
      const nodeIndex = RatchetTree.leafToNode(i);
      if (this.getNode(nodeIndex) === null) {
        return i;
      }
    }
    return null;
  }

  /**
   * Clone the tree
   */
  clone(): RatchetTree {
    return new RatchetTree(this.suite, [...this.nodes]);
  }

  /**
   * Compute commit secret from an update path
   */
  computeCommitSecret(
    senderIndex: LeafIndex,
    updatePath: UpdatePath,
  ): Uint8Array {
    // This is a simplified implementation
    // In a full implementation, this would derive the commit secret from the path secrets
    const encoder = new Encoder();
    encoder.writeUint32(senderIndex);
    encoder.writeBytes(updatePath.leafNode.encryptionKey);
    for (const node of updatePath.nodes) {
      encoder.writeBytes(node.encryptionKey);
    }
    return hash(this.suite, encoder.finish());
  }

  /**
   * Apply an update path to the tree
   */
  applyUpdatePath(senderIndex: LeafIndex, updatePath: UpdatePath): void {
    // Update the sender's leaf
    this.updateLeaf(senderIndex, updatePath.leafNode);

    // Update nodes along the direct path
    const directPath = this.directPath(senderIndex);
    for (let i = 0; i < updatePath.nodes.length && i < directPath.length; i++) {
      const nodeIndex = directPath[i];
      const updateNode = updatePath.nodes[i];

      // Create parent node with new public key
      const parentNode: ParentNode = {
        encryptionKey: updateNode.encryptionKey,
        parentHash: new Uint8Array(0), // Will be computed later
        unmergedLeaves: [],
      };

      this.setNode(nodeIndex, parentNode);
    }
  }

  /**
   * Export tree state
   */
  export(): { suite: CipherSuite; nodes: (RatchetNode | null)[] } {
    return {
      suite: this.suite,
      nodes: [...this.nodes],
    };
  }

  /**
   * Import tree state
   */
  static import(
    data: { suite: CipherSuite; nodes: (RatchetNode | null)[] },
  ): RatchetTree {
    return new RatchetTree(data.suite, data.nodes);
  }
}
