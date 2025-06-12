/**
 * Ratchet tree implementation for MLS
 * Based on RFC 9420 Section 4 and Section 7
 * Improved architecture inspired by OpenMLS treesync
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
 * Strongly typed leaf node index
 */
export class TypedLeafIndex {
  constructor(public readonly value: number) {
    if (value < 0 || !Number.isInteger(value)) {
      throw new RatchetTreeError("Invalid leaf index");
    }
  }

  toNodeIndex(): TypedNodeIndex {
    return new TypedNodeIndex(this.value * 2);
  }

  toString(): string {
    return `Leaf(${this.value})`;
  }
}

/**
 * Strongly typed parent node index
 */
export class TypedParentIndex {
  constructor(public readonly value: number) {
    if (value < 0 || !Number.isInteger(value)) {
      throw new RatchetTreeError("Invalid parent index");
    }
  }

  toNodeIndex(): TypedNodeIndex {
    return new TypedNodeIndex(this.value * 2 + 1);
  }

  toString(): string {
    return `Parent(${this.value})`;
  }
}

/**
 * Strongly typed node index (either leaf or parent)
 */
export class TypedNodeIndex {
  constructor(public readonly value: number) {
    // Handle NaN and infinite values gracefully
    if (!Number.isFinite(value)) {
      throw new RatchetTreeError(`Invalid node index: ${value}`);
    }

    // Convert to integer if it's a floating point number
    const intValue = Math.floor(value);
    if (intValue < 0) {
      throw new RatchetTreeError(
        `Invalid node index: ${intValue} (must be non-negative)`,
      );
    }

    // Store the integer value
    (this as any).value = intValue;
  }

  isLeaf(): boolean {
    return this.value % 2 === 0;
  }

  isParent(): boolean {
    return this.value % 2 === 1;
  }

  toLeafIndex(): TypedLeafIndex {
    if (!this.isLeaf()) {
      throw new RatchetTreeError("Node is not a leaf");
    }
    return new TypedLeafIndex(this.value / 2);
  }

  toParentIndex(): TypedParentIndex {
    if (!this.isParent()) {
      throw new RatchetTreeError("Node is not a parent");
    }
    return new TypedParentIndex((this.value - 1) / 2);
  }

  toString(): string {
    return this.isLeaf()
      ? `Node(Leaf,${this.value})`
      : `Node(Parent,${this.value})`;
  }
}

/**
 * Tree hash input for leaf nodes (RFC 9420)
 */
interface LeafNodeHashInput {
  leafIndex: number;
  leafNode?: LeafNode;
}

/**
 * Tree hash input for parent nodes (RFC 9420)
 */
interface ParentNodeHashInput {
  parentNode?: ParentNode;
  leftHash: Uint8Array;
  rightHash: Uint8Array;
}

/**
 * Tree hash input structure (RFC 9420)
 */
interface TreeHashInput {
  nodeType: NodeType;
  content: LeafNodeHashInput | ParentNodeHashInput;
}

/**
 * Ratchet tree error types
 */
export class RatchetTreeError extends Error {
  constructor(message: string, public override readonly cause?: Error) {
    super(message);
    this.name = "RatchetTreeError";
  }
}

/**
 * Ratchet tree implementation with improved architecture
 * Inspired by OpenMLS treesync design patterns
 */
export class RatchetTree {
  private leafNodes: (LeafNode | null)[];
  private parentNodes: (ParentNode | null)[];
  private suite: CipherSuite;
  private actualLeafCount: number = 0;

  constructor(suite: CipherSuite, nodes?: (RatchetNode | null)[]) {
    this.suite = suite;
    this.leafNodes = [];
    this.parentNodes = [];

    if (nodes) {
      this.importFromFlatArray(nodes);
    }
  }

  /**
   * Import from flat array representation (backward compatibility)
   */
  private importFromFlatArray(nodes: (RatchetNode | null)[]): void {
    let maxLeaf = -1;

    // Split nodes into leaf and parent arrays
    for (let i = 0; i < nodes.length; i++) {
      if (i % 2 === 0) {
        // Leaf node
        const leafIndex = i / 2;
        while (this.leafNodes.length <= leafIndex) {
          this.leafNodes.push(null);
        }
        this.leafNodes[leafIndex] = nodes[i] as LeafNode | null;

        if (nodes[i] !== null) {
          maxLeaf = leafIndex;
        }
      } else {
        // Parent node
        const parentIndex = (i - 1) / 2;
        while (this.parentNodes.length <= parentIndex) {
          this.parentNodes.push(null);
        }
        this.parentNodes[parentIndex] = nodes[i] as ParentNode | null;
      }
    }

    this.actualLeafCount = maxLeaf + 1;
  }

  /**
   * Export to flat array representation (backward compatibility)
   */
  private exportToFlatArray(): (RatchetNode | null)[] {
    const maxIndex = this.rootIndex();
    const nodes: (RatchetNode | null)[] = new Array(maxIndex + 1).fill(null);

    // Copy leaf nodes
    this.leafNodes.forEach((leaf, index) => {
      const nodeIndex = index * 2;
      if (nodeIndex <= maxIndex) {
        nodes[nodeIndex] = leaf;
      }
    });

    // Copy parent nodes
    this.parentNodes.forEach((parent, index) => {
      const nodeIndex = index * 2 + 1;
      if (nodeIndex <= maxIndex) {
        nodes[nodeIndex] = parent;
      }
    });

    return nodes;
  }

  /**
   * Get the number of leaves in the tree
   */
  get leafCount(): number {
    return this.actualLeafCount;
  }

  /**
   * Get total size (number of leaves) - alias for leafCount
   */
  size(): number {
    return this.leafCount;
  }

  /**
   * Get the depth of the tree
   * For a complete tree with N leaves, depth is ceil(log2(N))
   */
  get depth(): number {
    if (this.leafCount <= 1) return 0;
    return Math.ceil(Math.log2(this.leafCount));
  }

  /**
   * Get a node by typed index
   */
  getNodeByTypedIndex(index: TypedNodeIndex): RatchetNode | null {
    if (index.isLeaf()) {
      const leafIndex = index.toLeafIndex();
      return this.leafNodes[leafIndex.value] || null;
    } else {
      const parentIndex = index.toParentIndex();
      return this.parentNodes[parentIndex.value] || null;
    }
  }

  /**
   * Get a node by raw index (backward compatibility)
   */
  getNode(index: NodeIndex): RatchetNode | null {
    const typedIndex = new TypedNodeIndex(index);
    return this.getNodeByTypedIndex(typedIndex);
  }

  /**
   * Get a leaf node by leaf index
   */
  getLeafNode(leafIndex: LeafIndex): LeafNode | null {
    return this.leafNodes[leafIndex] || null;
  }

  /**
   * Get a leaf node by typed index
   */
  getLeafNodeByTypedIndex(leafIndex: TypedLeafIndex): LeafNode | null {
    return this.leafNodes[leafIndex.value] || null;
  }

  /**
   * Set a node by typed index
   */
  setNodeByTypedIndex(index: TypedNodeIndex, node: RatchetNode | null): void {
    if (index.isLeaf()) {
      const leafIndex = index.toLeafIndex();
      while (this.leafNodes.length <= leafIndex.value) {
        this.leafNodes.push(null);
      }
      this.leafNodes[leafIndex.value] = node as LeafNode | null;
    } else {
      const parentIndex = index.toParentIndex();
      while (this.parentNodes.length <= parentIndex.value) {
        this.parentNodes.push(null);
      }
      this.parentNodes[parentIndex.value] = node as ParentNode | null;
    }
  }

  /**
   * Set a node by raw index (backward compatibility)
   */
  setNode(index: NodeIndex, node: RatchetNode | null): void {
    const typedIndex = new TypedNodeIndex(index);
    this.setNodeByTypedIndex(typedIndex, node);
  }

  /**
   * Get the parent index of a node (RFC 9420 array representation)
   */
  static parent(index: NodeIndex): NodeIndex {
    const x = index;
    const k = this.level(x);
    const b = (x >> (k + 1)) & 0x01;
    return (x | (1 << k)) ^ (b << (k + 1));
  }

  /**
   * Get the left child index of a parent node (RFC 9420 array representation)
   */
  static leftChild(index: NodeIndex): NodeIndex {
    const x = index;
    const k = this.level(x);
    if (k === 0) {
      throw new RatchetTreeError("Leaf node has no children");
    }
    return x ^ (0x01 << (k - 1));
  }

  /**
   * Get the right child index of a parent node (RFC 9420 array representation)
   */
  static rightChild(index: NodeIndex): NodeIndex {
    const x = index;
    const k = this.level(x);
    if (k === 0) {
      throw new RatchetTreeError("Leaf node has no children");
    }
    return x ^ (0x03 << (k - 1));
  }

  /**
   * Get the sibling index of a node (RFC 9420 array representation)
   * The sibling is the other child of the same parent
   */
  static sibling(index: NodeIndex): NodeIndex {
    const parentIndex = this.parent(index);

    // If this node is the left child, return the right child
    // If this node is the right child, return the left child
    if (index < parentIndex) {
      return this.rightChild(parentIndex);
    } else {
      return this.leftChild(parentIndex);
    }
  }

  /**
   * Get the level of a node (RFC 9420 array representation)
   * Level is the number of trailing 1 bits
   */
  static level(index: NodeIndex): number {
    let level = 0;
    let temp = index;

    // Count trailing 1 bits
    while ((temp & 1) === 1 && temp > 0) {
      level++;
      temp >>= 1;
    }

    return level;
  }

  /**
   * Get parent as TypedNodeIndex (for internal use)
   */
  static parentTyped(index: TypedNodeIndex | NodeIndex): TypedNodeIndex {
    const rawIndex = index instanceof TypedNodeIndex ? index.value : index;
    return new TypedNodeIndex(this.parent(rawIndex));
  }

  /**
   * Validate tree structure (based on OpenMLS validation)
   */
  validate(): void {
    // Check for trailing blank nodes
    if (this.leafCount === 0) {
      throw new RatchetTreeError("Tree cannot be empty");
    }

    // Validate leaf nodes are in correct positions
    for (let i = 0; i < this.leafCount; i++) {
      const leafIndex = new TypedLeafIndex(i);
      const nodeIndex = leafIndex.toNodeIndex();

      if (!nodeIndex.isLeaf()) {
        throw new RatchetTreeError(`Invalid leaf position at index ${i}`);
      }
    }

    // Validate parent nodes are in correct positions
    for (let i = 0; i < this.parentNodes.length; i++) {
      const parentIndex = new TypedParentIndex(i);
      const nodeIndex = parentIndex.toNodeIndex();

      if (!nodeIndex.isParent()) {
        throw new RatchetTreeError(`Invalid parent position at index ${i}`);
      }
    }

    // Check tree structure consistency
    if (this.leafCount > 1) {
      const rootIndex = this.getRootIndex();
      this.validateSubtree(rootIndex);
    }
  }

  /**
   * Validate subtree structure recursively
   */
  private validateSubtree(index: TypedNodeIndex, depth = 0): void {
    if (depth > 32) {
      throw new RatchetTreeError("Tree depth exceeds maximum");
    }

    if (index.isLeaf()) {
      return; // Leaf nodes are always valid
    }

    // Check parent node has valid children
    const leftChild = new TypedNodeIndex(RatchetTree.leftChild(index.value));
    const rightChild = new TypedNodeIndex(RatchetTree.rightChild(index.value));

    this.validateSubtree(leftChild, depth + 1);
    this.validateSubtree(rightChild, depth + 1);
  }

  /**
   * Get the root index as typed index
   */
  getRootIndex(): TypedNodeIndex {
    if (this.leafCount === 0) return new TypedNodeIndex(0);
    if (this.leafCount === 1) return new TypedNodeIndex(0); // Single leaf is its own root

    // For N leaves, root is at index: 2^ceil(log2(N)) - 1
    // This follows RFC 9420's complete binary tree structure
    const depth = Math.ceil(Math.log2(this.leafCount));
    return new TypedNodeIndex((1 << depth) - 1);
  }

  /**
   * Get the root index (backward compatibility)
   */
  rootIndex(): NodeIndex {
    return this.getRootIndex().value;
  }

  /**
   * Convert leaf index to node index (backward compatibility)
   */
  static leafToNode(leafIndex: LeafIndex): NodeIndex {
    return new TypedLeafIndex(leafIndex).toNodeIndex().value;
  }

  /**
   * Convert node index to leaf index (backward compatibility)
   */
  static nodeToLeaf(nodeIndex: NodeIndex): LeafIndex {
    return new TypedNodeIndex(nodeIndex).toLeafIndex().value;
  }

  /**
   * Improved tree hash computation with proper RFC 9420 structure
   */
  computeTreeHashStructured(index: TypedNodeIndex): Uint8Array {
    const input = this.createTreeHashInput(index);
    return this.hashTreeHashInput(input);
  }

  /**
   * Create tree hash input structure (RFC 9420 compliant)
   */
  private createTreeHashInput(index: TypedNodeIndex): TreeHashInput {
    if (index.isLeaf()) {
      const leafIndex = index.toLeafIndex();
      const leafNode = this.getLeafNodeByTypedIndex(leafIndex);

      return {
        nodeType: NodeType.LEAF,
        content: {
          leafIndex: leafIndex.value,
          leafNode: leafNode || undefined,
        } as LeafNodeHashInput,
      };
    } else {
      const parentIndex = index.toParentIndex();
      const parentNode = this.parentNodes[parentIndex.value] || undefined;

      // Recursively compute child hashes
      const leftChild = new TypedNodeIndex(RatchetTree.leftChild(index.value));
      const rightChild = new TypedNodeIndex(
        RatchetTree.rightChild(index.value),
      );
      const leftHash = this.computeTreeHashStructured(leftChild);
      const rightHash = this.computeTreeHashStructured(rightChild);

      return {
        nodeType: NodeType.PARENT,
        content: {
          parentNode,
          leftHash,
          rightHash,
        } as ParentNodeHashInput,
      };
    }
  }

  /**
   * Hash a tree hash input structure
   */
  private hashTreeHashInput(input: TreeHashInput): Uint8Array {
    const encoder = new Encoder();

    encoder.writeUint8(input.nodeType);

    if (input.nodeType === NodeType.LEAF) {
      const content = input.content as LeafNodeHashInput;
      encoder.writeUint32(content.leafIndex);

      if (content.leafNode) {
        encoder.writeUint8(1); // Present
        encoder.writeBytes(encodeLeafNode(content.leafNode));
      } else {
        encoder.writeUint8(0); // Absent
      }
    } else {
      const content = input.content as ParentNodeHashInput;

      if (content.parentNode) {
        encoder.writeUint8(1); // Present
        encoder.writeBytes(encodeParentNode(content.parentNode));
      } else {
        encoder.writeUint8(0); // Absent
      }

      encoder.writeVarintVector(content.leftHash);
      encoder.writeVarintVector(content.rightHash);
    }

    return hash(this.suite, encoder.finish());
  }

  /**
   * Improved direct path computation with typed indices
   */
  getDirectPath(leafIndex: TypedLeafIndex): TypedNodeIndex[] {
    const path: TypedNodeIndex[] = [];
    let nodeIndex = leafIndex.toNodeIndex();
    const rootIdx = this.getRootIndex();

    if (nodeIndex.value === rootIdx.value || this.leafCount <= 1) {
      return path;
    }

    let iterCount = 0;
    while (nodeIndex.value !== rootIdx.value) {
      if (iterCount++ > 32) {
        throw new RatchetTreeError("Infinite loop detected in direct path");
      }

      const parentIdx = RatchetTree.parentTyped(nodeIndex);
      path.push(parentIdx);
      nodeIndex = parentIdx;
    }

    return path;
  }

  /**
   * Get the direct path from a leaf to the root (backward compatibility)
   */
  directPath(leafIndex: LeafIndex): NodeIndex[] {
    const typedPath = this.getDirectPath(new TypedLeafIndex(leafIndex));
    return typedPath.map((idx) => idx.value);
  }

  /**
   * Get the copath of a leaf with typed indices
   */
  getCopath(leafIndex: TypedLeafIndex): TypedNodeIndex[] {
    const copath: TypedNodeIndex[] = [];
    let nodeIndex = leafIndex.toNodeIndex();
    const rootIdx = this.getRootIndex();

    if (nodeIndex.value === rootIdx.value || this.leafCount <= 1) {
      return copath;
    }

    let iterCount = 0;
    while (nodeIndex.value !== rootIdx.value) {
      if (iterCount++ > 32) {
        throw new RatchetTreeError("Infinite loop detected in copath");
      }

      const siblingIdx = new TypedNodeIndex(
        RatchetTree.sibling(nodeIndex.value),
      );
      copath.push(siblingIdx);
      nodeIndex = RatchetTree.parentTyped(nodeIndex);
    }

    return copath;
  }

  /**
   * Get the copath of a leaf (backward compatibility)
   */
  copath(leafIndex: LeafIndex): NodeIndex[] {
    const typedCopath = this.getCopath(new TypedLeafIndex(leafIndex));
    return typedCopath.map((idx) => idx.value);
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
   * Check if a node is blank
   */
  isBlank(index: NodeIndex): boolean {
    return this.getNode(index) === null;
  }

  /**
   * Check if a node is a leaf
   */
  isLeaf(index: NodeIndex): boolean {
    return new TypedNodeIndex(index).isLeaf();
  }

  /**
   * Improved tree hash computation (uses structured approach)
   */
  treeHash(): Uint8Array {
    const rootIndex = this.getRootIndex();
    return this.computeTreeHashStructured(rootIndex);
  }

  /**
   * Legacy tree hash computation (for backward compatibility)
   */
  computeTreeHash(index: NodeIndex, depth = 0): Uint8Array {
    const typedIndex = new TypedNodeIndex(index);
    return this.computeTreeHashStructured(typedIndex);
  }

  /**
   * Get the resolution of a node with improved error handling
   */
  resolve(index: NodeIndex, depth = 0): NodeIndex[] {
    if (depth > 32) {
      throw new RatchetTreeError("Infinite recursion detected in resolve");
    }

    const typedIndex = new TypedNodeIndex(index);

    // Bounds check
    if (typedIndex.isLeaf() && typedIndex.value / 2 >= this.leafNodes.length) {
      return [];
    }
    if (
      typedIndex.isParent() &&
      (typedIndex.value - 1) / 2 >= this.parentNodes.length
    ) {
      return [];
    }

    const node = this.getNodeByTypedIndex(typedIndex);

    // Non-blank node
    if (node !== null) {
      const resolution = [index];

      // Add unmerged leaves for parent nodes
      if (typedIndex.isParent() && "unmergedLeaves" in node) {
        const parentNode = node as ParentNode;
        for (const leafIdx of parentNode.unmergedLeaves) {
          resolution.push(RatchetTree.leafToNode(leafIdx));
        }
      }

      return resolution;
    }

    // Blank leaf
    if (typedIndex.isLeaf()) {
      return [];
    }

    // Blank parent - concatenate resolutions of children
    const left = RatchetTree.leftChild(index);
    const right = RatchetTree.rightChild(index);
    return [
      ...this.resolve(left, depth + 1),
      ...this.resolve(right, depth + 1),
    ];
  }

  /**
   * Blank a node and its ancestors
   */
  blank(index: NodeIndex): void {
    this.setNode(index, null);

    // Blank ancestors
    let current = index;
    const rootIndex = this.rootIndex();

    let iterCount = 0;
    while (current !== rootIndex) {
      if (iterCount++ > 32) {
        throw new RatchetTreeError("Infinite loop detected in blank");
      }

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
    const rootIndex = this.rootIndex();

    let iterCount = 0;
    while (current !== rootIndex) {
      if (iterCount++ > 32) {
        throw new RatchetTreeError("Infinite loop detected in merge");
      }

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
    const newLeafIndex = this.actualLeafCount;

    // Ensure arrays are large enough
    while (this.leafNodes.length <= newLeafIndex) {
      this.leafNodes.push(null);
    }

    this.leafNodes[newLeafIndex] = leaf;
    this.actualLeafCount++;

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
    this.leafNodes.forEach((_, index) => {
      const node = this.leafNodes[index];
      // Note: Leaf nodes don't have unmerged leaves, only parent nodes do
    });

    this.parentNodes.forEach((node, index) => {
      if (node && "unmergedLeaves" in node) {
        const parentNode = node as ParentNode;
        parentNode.unmergedLeaves = parentNode.unmergedLeaves.filter(
          (idx) => idx !== leafIndex,
        );
      }
    });

    // Truncate if possible
    this.truncate();
  }

  /**
   * Update a leaf in the tree
   */
  updateLeaf(leafIndex: LeafIndex, newLeaf: LeafNode): void {
    if (leafIndex >= this.leafNodes.length) {
      while (this.leafNodes.length <= leafIndex) {
        this.leafNodes.push(null);
      }
    }
    this.leafNodes[leafIndex] = newLeaf;
  }

  /**
   * Extend the tree by one level (simplified for new architecture)
   */
  private extend(): void {
    // In the new architecture, extension is handled more naturally
    // by the separate leaf and parent arrays
    throw new RatchetTreeError(
      "Tree extension not yet implemented in new architecture",
    );
  }

  /**
   * Truncate the tree if the right subtree is empty
   */
  private truncate(): void {
    // Simplified truncation - remove trailing null entries
    while (
      this.leafNodes.length > 0 &&
      this.leafNodes[this.leafNodes.length - 1] === null
    ) {
      this.leafNodes.pop();
      this.actualLeafCount = Math.max(0, this.actualLeafCount - 1);
    }

    while (
      this.parentNodes.length > 0 &&
      this.parentNodes[this.parentNodes.length - 1] === null
    ) {
      this.parentNodes.pop();
    }
  }

  /**
   * Check if a subtree is empty (all nodes are blank)
   */
  private isSubtreeEmpty(index: NodeIndex, depth = 0): boolean {
    if (depth > 32) {
      throw new RatchetTreeError(
        "Infinite recursion detected in isSubtreeEmpty",
      );
    }

    const typedIndex = new TypedNodeIndex(index);

    if (this.getNodeByTypedIndex(typedIndex) !== null) {
      return false;
    }

    if (typedIndex.isLeaf()) {
      return true;
    }

    const left = RatchetTree.leftChild(index);
    const right = RatchetTree.rightChild(index);

    return this.isSubtreeEmpty(left, depth + 1) &&
      this.isSubtreeEmpty(right, depth + 1);
  }

  /**
   * Compute parent hash for a node (improved implementation)
   */
  computeParentHash(index: NodeIndex, copath: NodeIndex): Uint8Array {
    const typedIndex = new TypedNodeIndex(index);
    const node = this.getNodeByTypedIndex(typedIndex);

    if (!node) {
      throw new RatchetTreeError("Cannot compute parent hash for blank node");
    }

    const encoder = new Encoder();

    // Encryption key
    encoder.writeVarintVector(node.encryptionKey);

    // Parent hash (empty for root)
    if (index === this.rootIndex()) {
      encoder.writeVarintVector(new Uint8Array(0));
    } else if ("parentHash" in node) {
      const parentNode = node as ParentNode;
      encoder.writeVarintVector(parentNode.parentHash);
    } else {
      encoder.writeVarintVector(new Uint8Array(0));
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
    // For now, use the regular tree hash
    // In a full implementation, this would handle exclusion of unmerged leaves
    return this.computeTreeHash(index);
  }

  /**
   * Get all occupied leaf indices
   */
  getOccupiedLeaves(): LeafIndex[] {
    const leaves: LeafIndex[] = [];

    for (let i = 0; i < this.leafNodes.length; i++) {
      if (this.leafNodes[i] !== null) {
        leaves.push(i);
      }
    }

    return leaves;
  }

  /**
   * Find a free leaf slot
   */
  findFreeLeaf(): LeafIndex | null {
    for (let i = 0; i < this.leafNodes.length; i++) {
      if (this.leafNodes[i] === null) {
        return i;
      }
    }
    return null;
  }

  /**
   * Clone the tree
   */
  clone(): RatchetTree {
    const cloned = new RatchetTree(this.suite);
    cloned.leafNodes = [...this.leafNodes];
    cloned.parentNodes = [...this.parentNodes];
    cloned.actualLeafCount = this.actualLeafCount;
    return cloned;
  }

  /**
   * Compute commit secret from an update path
   */
  computeCommitSecret(
    senderIndex: LeafIndex,
    updatePath: UpdatePath,
  ): Uint8Array {
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
      const typedIndex = new TypedNodeIndex(nodeIndex);

      if (typedIndex.isParent()) {
        // Create parent node with new public key
        const parentNode: ParentNode = {
          encryptionKey: updateNode.encryptionKey,
          parentHash: new Uint8Array(0), // Will be computed later
          unmergedLeaves: [],
        };

        this.setNodeByTypedIndex(typedIndex, parentNode);
      }
    }
  }

  /**
   * Export tree state (updated for new architecture)
   */
  export(): { suite: CipherSuite; nodes: (RatchetNode | null)[] } {
    return {
      suite: this.suite,
      nodes: this.exportToFlatArray(),
    };
  }

  /**
   * Import tree state (updated for new architecture)
   */
  static import(
    data: { suite: CipherSuite; nodes: (RatchetNode | null)[] },
  ): RatchetTree {
    return new RatchetTree(data.suite, data.nodes);
  }

  /**
   * Debug information (useful for development and testing)
   */
  debug(): {
    leafCount: number;
    leafNodes: number;
    parentNodes: number;
    rootIndex: number;
    depth: number;
  } {
    return {
      leafCount: this.leafCount,
      leafNodes: this.leafNodes.filter((n) => n !== null).length,
      parentNodes: this.parentNodes.filter((n) => n !== null).length,
      rootIndex: this.rootIndex(),
      depth: this.depth,
    };
  }
}
