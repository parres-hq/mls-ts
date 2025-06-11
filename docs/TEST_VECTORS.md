# MLS Protocol Test Vectors

## ⚠️ Test Status

**Limited test coverage** - Only basic unit tests implemented. Full RFC
compliance testing required.

## Overview

This document tracks the test vectors we need to implement for RFC 9420
compliance and our current testing status.

## Current Test Implementation

### ✅ Implemented Tests (11 passing)

- **Crypto operations** (src/test/basic.test.ts - 7 tests)
  - HPKE key pair generation
  - Signature key pair generation
  - Sign and verify operations
  - Hash operations
  - Ratchet tree basic operations
  - Key schedule epoch 0 initialization
  - Storage operations (skipped in Deno environment)

- **Client operations** (src/test/client.test.ts - 4 tests)
  - Client creation and initialization
  - KeyPackage generation for multiple cipher suites
  - KeyPackage lifetime validation
  - Client configuration updates

### 🔴 Missing Critical Tests

- **HPKE Operations** - No encryption/decryption tests
- **Wire Format** - No encoding/decoding validation
- **Tree Hashing** - No tree hash verification
- **Key Schedule** - No epoch transition tests
- **Message Layer** - Not implemented yet
- **Protocol State** - Not implemented yet

## Test Vector Sources

1. **RFC 9420 Examples**
   - Tree hash computations (Appendix A)
   - Parent hash evolution (Appendix B)
   - Key schedule outputs

2. **MLS Working Group Vectors**
   - Repository: https://github.com/mlswg/mls-implementations
   - Interoperability test vectors
   - Cross-implementation validation

3. **Cipher Suite Specific**
   - HPKE test vectors (RFC 9180)
   - Signature test vectors
   - KDF test vectors

## Critical Test Cases

### 1. Tree Operations

```typescript
// Test: Tree extension from 2 to 4 members
const tree_2_members = new RatchetTree(suite);
// Add A, B
// Verify tree structure

const tree_4_members = tree_2_members.clone();
// Add C, D
// Verify:
// - Root changed
// - Previous subtree intact
// - Correct parent/child relationships
```

### 2. Key Schedule

```typescript
// Test: Epoch transition
const epoch0_secrets = keySchedule.initEpoch0();
// Verify against known values

const epoch1_secrets = keySchedule.nextEpoch(commit_secret);
// Verify:
// - Correct init_secret chaining
// - All derived secrets match expected
```

### 3. UpdatePath Validation

```typescript
// Test: Path secret derivation
const path_secrets = derivePathSecrets(leaf_secret);
// Verify:
// - Correct chaining
// - Proper encryption to copath nodes
```

### 4. Message Encryption

```typescript
// Test: Application message encryption/decryption
const plaintext = new TextEncoder().encode("Hello MLS");
const ciphertext = group.encrypt(plaintext);
const decrypted = group.decrypt(ciphertext);
// Verify:
// - Correct generation increment
// - Proper AAD inclusion
// - Nonce uniqueness
```

## Negative Test Cases

### 1. Invalid Signatures

- Wrong signature key
- Modified content
- Expired credentials

### 2. Tree Violations

- Adding to occupied leaf
- Invalid parent hashes
- Malformed UpdatePath

### 3. Epoch Violations

- Old epoch messages
- Future epoch messages
- Replayed messages

### 4. Cryptographic Failures

- Wrong decryption keys
- Modified ciphertexts
- Invalid KEM outputs

## Fuzzing Targets

1. **Encoding/Decoding**
   - Random byte sequences
   - Truncated messages
   - Oversized vectors

2. **Tree Operations**
   - Random add/remove sequences
   - Large trees (>1000 members)
   - Concurrent modifications

3. **State Machine**
   - Random proposal sequences
   - Invalid state transitions
   - Concurrent commits

## Performance Benchmarks

### Target Metrics

- KeyPackage generation: <10ms
- Add member to 100-person group: <50ms
- Encrypt message in 1000-person group: <5ms
- Tree hash computation (1000 nodes): <20ms

### Benchmark Suite

```typescript
// benchmark/tree_ops.ts
Deno.bench("Add 100 members", () => {
  const tree = new RatchetTree(suite);
  for (let i = 0; i < 100; i++) {
    tree.addLeaf(generateLeaf());
  }
});

// benchmark/crypto_ops.ts
Deno.bench("Generate 100 KeyPackages", () => {
  for (let i = 0; i < 100; i++) {
    generateKeyPackage();
  }
});
```

## Interoperability Matrix

| Implementation | Wire Format | Tree Ops | Key Schedule | Messages |
| -------------- | ----------- | -------- | ------------ | -------- |
| mls-ts (ours)  | ✅          | ✅       | ✅           | 🚧       |
| OpenMLS        | -           | -        | -            | -        |
| Cisco MLS      | -           | -        | -            | -        |
| MLSpp          | -           | -        | -            | -        |

Legend: ✅ Implemented, 🚧 In Progress, ❌ Not Started, - Not Tested

## Validation Checklist

- [ ] All RFC test vectors passing
- [ ] Interop with at least one other implementation
- [ ] Fuzzing runs for 24 hours without crashes
- [ ] Performance benchmarks meet targets
- [ ] Security properties validated
  - [ ] Forward secrecy
  - [ ] Post-compromise security
  - [ ] Authentication
  - [ ] Confidentiality
