# MLS Implementation Quick Reference

## ⚠️ Security Status

**NOT PRODUCTION READY** - See [SECURITY_ANALYSIS.md](./SECURITY_ANALYSIS.md) for a detailed assessment. Implementation is for research/educational use.

## Implementation Status (May 2025)

-   ✅ **Completed Components**:
    -   `src/types.ts` (Core MLS Types)
    -   `src/crypto.ts` (Cryptographic Operations, uses @noble)
    -   `src/encoding.ts` (Wire Format Encoding/Decoding)
    -   `src/ratchet-tree.ts` (Ratchet Tree Operations)
    -   `src/key-schedule.ts` (Key Schedule & Epoch Secret Derivation)
    -   `src/storage.ts` & `src/storage-memory.ts` (Storage Interface & In-Memory Backend)
    -   `src/client.ts` (MLSClient for KeyPackage Management)
    -   `src/hpke.ts` (Full RFC 9180 HPKE Implementation)
-   🚧 **Partially Implemented / In Progress**:
    -   `src/group.ts` (MLSGroup Operations - basic structure exists, key functions like join, full commit processing, and message crypto integration are TODO)
-   🔵 **Not Started / Needs Creation**:
    -   `src/message.ts` (Message Framing: PublicMessage, PrivateMessage, HPKE integration for content) - **CRITICAL NEXT STEP**
    -   Protocol State Machine & Validation (Across group.ts and potentially new modules)
    -   Full anExternal Commits
    -   Advanced Security Hardening (e.g., encryption at rest, full credential validation beyond basic)

## Key Files and Their Purposes

```
src/
├── client.ts       # ✅ Client management (KeyPackages, Identity)
├── crypto.ts       # ✅ Cryptographic operations (Signatures, KDF, AEAD)
├── encoding.ts     # ✅ Wire format handling (TLS-style)
├── group.ts        # 🚧 Group operations (Partially implemented)
├── hpke.ts         # ✅ Full HPKE implementation (RFC 9180)
├── key-schedule.ts # ✅ Key derivation & epoch secrets
├── mod.ts          # Main module exports
├── ratchet-tree.ts # ✅ Tree operations & management
├── storage-memory.ts # ✅ In-memory storage backend
├── storage.ts      # ✅ Storage interface
└── types.ts        # ✅ Core MLS types and structures

docs/
└── api-design.ts   # High-level API blueprint/design document (not executable code)
```

## Critical Functions & Concepts (Simplified)

### HPKE (`src/hpke.ts`)
```typescript
// Setup for sending (encrypting)
hpkeContextS = setupBaseS(suite, recipientPublicKey, info);
ciphertext = hpkeContextS.seal(aad, plaintext);

// Setup for receiving (decrypting)
hpkeContextR = setupBaseR(suite, encappedKey, recipientPrivateKey, info);
plaintext = hpкеContextR.open(aad, ciphertext);

// Single-shot (combines setup and seal/open)
encrypted = seal(suite, recipientPublicKey, info, aad, plaintext);
decrypted = open(suite, encappedKey, recipientPrivateKey, info, aad, ciphertext);
```

### Client (`src/client.ts`)
```typescript
client = new MLSClient(identity, storage);
keyPackage = await client.createKeyPackage(cipherSuite);
```

### Group (`src/group.ts` - Note: Many operations are placeholders or incomplete)
```typescript
// Conceptual - actual API may evolve
group = await MLSGroup.create(groupId, cipherSuite, myIdentity, storage); // Basic creation
proposalRef = await group.addMember(keyPackage); // Propose Add
// commitResult = await group.commit(); // Process proposals (Simplified)
// mlsMessage = await group.encryptMessage(plaintext); // Encrypt (Placeholder)
```

### Key MLS Structures (from `src/types.ts`)
-   `KeyPackage`, `LeafNode`, `Credential`
-   `GroupContext`, `GroupSecrets`, `Welcome`
-   `FramedContent`, `PublicMessage`, `PrivateMessage` (Latter two to be fully defined in `src/message.ts`)
-   `Proposal` (Add, Update, Remove, Psk, GroupContextExtensions, ExternalInit, ReInit), `Commit`

## Protocol Constants (Examples)
```typescript
ProtocolVersion.MLS10 // 0x0001
CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 // 0x0001
ContentType.APPLICATION // 1
ContentType.PROPOSAL    // 2
ContentType.COMMIT      // 3
```

## Key Security Mechanisms Handled
-   **Confidentiality & Integrity of Messages**: Primarily via HPKE for `PrivateMessage` (to be built in `src/message.ts`).
-   **Authentication**: Signatures on KeyPackages, LeafNodes, `PublicMessage`s (to be built), Commits.
-   **Forward Secrecy & Post-Compromise Security**: Via tree ratcheting and epoch updates.

## Common Patterns (Target State)

### Creating & Sending a KeyPackage (via `MLSClient`)
1.  `client.createKeyPackage(cipherSuite)` generates HPKE keys, signature keys, LeafNode, and signs the KeyPackage.
2.  The KeyPackage is then shared out-of-band (e.g., to a directory server).

### Group Creation (Initiator - using `MLSGroup`)
1.  `MLSGroup.create(...)` sets up initial tree with self, initial GroupContext, derives initial epoch secrets.

### Adding a Member (using `MLSGroup`)
1.  Creator gets new member's KeyPackage.
2.  Creator calls `group.proposeAdd(keyPackage)`.
3.  Creator calls `group.commit()`:
    *   Applies Add proposal to tree.
    *   Generates `UpdatePath`.
    *   Derives new epoch secrets.
    *   Creates `Commit` message (to be framed via `src/message.ts`).
    *   Generates `Welcome` message, encrypting `GroupSecrets` for new member using HPKE (from new member's KeyPackage init key).
4.  Sends `Commit` to existing members, `Welcome` to new member.

### Encrypting an Application Message (Member - using `MLSGroup`)
1.  `group.encryptMessage(plaintext)`:
    *   (To be implemented in `src/group.ts` using `src/message.ts`)
    *   Gets current application encryption keys from KeySchedule's secret tree.
    *   Constructs `FramedContent` with application data.
    *   Encrypts using AEAD, appropriate nonce, and AAD.
    *   Packages into an MLS `PrivateMessage`.

## Testing Reminders
-   Use `deno test --allow-all`
-   `InMemoryStorage` is used for tests as IndexedDB isn't ideal for Deno's test runner.
-   Refer to `TEST_VECTORS.md` for RFC compliance goals.

## Next Implementation Priority

1.  🔵 **`src/message.ts` Creation & Implementation**:
    *   Define `PublicMessage` & `PrivateMessage`.
    *   Integrate HPKE for `PrivateMessage` content encryption.
    *   Implement sender authentication for `PublicMessage`.
2.  🚧 **`src/group.ts` Finalization**:
    *   Complete `joinFromWelcome`, `processCommit`.
    *   Integrate `src/message.ts` for framing Commits and encrypting application data.
    *   Implement Welcome message generation strategy.
    *   Implement robust state validation (Protocol State Machine).
3.  🛡️ **Protocol State Machine**: Ensure all operations are valid in the current group context.
