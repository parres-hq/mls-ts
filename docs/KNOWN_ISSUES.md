# Known Issues and Gotchas

## ✅ Resolved Issues

### 1. HPKE Implementation Formerly Incomplete ✅ SOLVED
**Issue (Previously)**: HPKE (RFC 9180) was not fully implemented.
**Status (Now)**: **COMPLETED**. Full RFC 9180 HPKE is implemented in `src/hpke.ts`, including all modes, authenticated encryption, context binding, and export mechanisms. All related tests are passing.

### 2. IndexedDB in Test Environment ✅ SOLVED
**Issue**: IndexedDB is not available in Deno test environment.
**Solution**: Implemented `InMemoryStorage` with automatic detection, allowing tests to run effectively.

## 🔴 Critical Security Limitations (Active)

### 1. No Message Encryption/Framing (`src/message.ts` Missing)
**Issue**: The MLS message layer (`PrivateMessage`, `PublicMessage`) is not implemented. While `src/hpke.ts` provides the cryptographic primitives, the actual framing and usage for message protection are missing.
**Impact**: Core functionality missing - no secure group messaging.
**Required**: Create `src/message.ts` and implement message framing and encryption/decryption using HPKE. **This is a top priority.**

### 2. Incomplete Protocol Validation & Group Operations
**Issue**: `src/group.ts` has foundational elements but lacks a complete state machine for validating proposals, commits, and epoch transitions. Key operations like `joinFromWelcome` and `processCommit` are not fully implemented or robust.
**Impact**: Invalid state transitions are possible, leading to security vulnerabilities and corrupted group states.
**Risk**: Protocol attacks, inconsistent group views among members.
**Required**: Finalize `src/group.ts` by implementing comprehensive state validation, completing all member operations, and integrating message crypto.

### 3. Keys Stored in Plaintext (Storage Encryption)
**Issue**: No encryption at rest in the storage layer (`src/storage.ts`, `src/storage-memory.ts`).
**Impact**: A local attacker with access to the storage medium can extract all keys.
**Mitigation**: Needs a key derivation function and encryption layer for stored sensitive materials. (Lower priority than message framing and group ops).

### 4. No Credential Validation
**Issue**: Credentials (e.g., `BasicCredential`) are accepted without full verification (like expiry checks, or mechanisms for more complex credential types).
**Impact**: Impersonation attacks might be possible if credential handling is not fully vetted.
**Required**: Implement thorough credential validation, checking expiry, and potentially a framework for pluggable credential verifiers. (Lower priority than message framing and group ops).

## Current Limitations

### 1. Missing Crypto Algorithms (X448/Ed448)
**Issue**: @noble libraries do not currently support X448 or Ed448.
**Current**: Using X25519/Ed25519 as robust alternatives.
**Impact**: Cipher suites MLS_128_DHKEMP384_AES128GCM_SHA384_P384 (0x0002), MLS_128_DHKEMX448_AES128GCM_SHA512_Ed448 (0x0004) and MLS_128_DHKEMP521_AES128GCM_SHA512_P521 (0x0006) cannot be fully supported as per RFC 9420 if they rely on these specific curves for KEM or Signature when P-384/P-521 are used for KEM and Ed448 for Signature. (Note: Check RFC specifics for which algorithm is used where). The current implementation supports P-256/384/521 for KEMs and Ed25519 for signatures. If Ed448 is strictly required for a cipher suite, that suite is not fully compliant.
**Future Fix**:
- Wait for @noble to add support.
- Integrate an alternative library for these specific algorithms (increases complexity).
- Formally mark affected cipher suites as unsupported or partially supported.

### 2. Type Safety Gaps
**Issue**: Using plain numbers for indices (e.g., `LeafIndex`, `NodeIndex`).
**Risk**: Potential to mix up `LeafIndex` and `NodeIndex` or other numeric identifiers.
**Future**: Implement branded types for enhanced type safety, as suggested in `DESIGN.md`.
```typescript
type LeafIndex = number & { readonly _brand: "LeafIndex" };
```

## Common Pitfalls
_(This section seems generally applicable and does not require changes based on current progress, so it's retained as is)_

### 1. Epoch Management
...
### 2. Tree Node Indices
...
### 3. Key Lifetime
...
### 4. Async Storage Operations
...

## Performance Gotchas
_(This section seems generally applicable and does not require changes)_
...

## Security Gotchas
_(This section seems generally applicable and does not require changes)_
...

## API Usage Gotchas
_(This section seems generally applicable and does not require changes)_
...

## Debugging Tips
_(This section seems generally applicable and does not require changes)_
...
