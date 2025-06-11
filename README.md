# MLS TypeScript/Deno Implementation

A TypeScript implementation of the Message Layer Security (MLS) protocol
(RFC 9420) for Deno, focusing on security and minimal external dependencies.

## ⚠️ Security Warning

**This implementation is NOT ready for production use.** It is currently
suitable for research and educational purposes only. Critical security features
are still under development. See [SECURITY_ANALYSIS.md](./SECURITY_ANALYSIS.md)
for details.

## Overview

This library aims to implement the MLS protocol for end-to-end encrypted group
messaging with:

- Forward secrecy
- Post-compromise security
- Asynchronous group key establishment
- Support for groups from 2 to thousands of members

## Current Status (June 2025)

### ✅ Fully Implemented

- **Core Protocol Infrastructure** (100% complete)
  - All MLS protocol types and structures (RFC 9420)
  - Complete wire format encoding/decoding
  - Full cryptographic operations using @noble libraries
  - Comprehensive ratchet tree implementation
  - Complete key schedule and epoch management
  - Flexible storage backend (IndexedDB/in-memory)

- **Client Layer** (100% complete)
  - MLSClient implementation with KeyPackage generation
  - Identity and credential management
  - Multi-cipher suite support
  - Storage integration

- **Group Operations** (95% complete)
  - Group creation and member management
  - Proposal system (Add, Remove, Update, PSK)
  - Commit processing with full state validation
  - External commit support for new member joins
  - Welcome message generation and processing
  - Pre-shared key (PSK) operations for resumption
  - Group resumption and branching operations

- **Message Processing** (90% complete)
  - PublicMessage handling (proposals, commits)
  - PrivateMessage encryption/decryption
  - Message authentication and validation
  - Replay protection mechanisms
  - Full HPKE implementation (RFC 9180)

- **State Machine Validation** (90% complete)
  - 13-step commit validation process
  - Epoch transition management
  - Tree integrity validation
  - Signature verification throughout

### 🚧 In Progress

- **Testing & Integration** (70% complete)
  - Basic functionality tests passing (20/20)
  - Multi-client integration scenarios
  - Performance benchmarking
  - RFC 9420 test vector validation

- **Production Readiness** (40% complete)
  - Input validation and bounds checking
  - Error handling improvements
  - Security hardening
  - Memory safety optimizations

### ⚠️ Security Status

**Current Assessment**: Research/Educational Quality
- ✅ Architecturally sound and RFC-compliant
- ✅ Using well-audited cryptographic libraries
- ✅ Strong TypeScript type safety
- ⚠️ Not yet security-audited
- ⚠️ Missing some production hardening
- ⚠️ Keys stored in memory (not secure storage)

## Features (When Complete)

- 🎯 RFC 9420 compliance
- 💾 Flexible storage backend (IndexedDB for browsers, in-memory for Deno/Node)
- 🔐 Secure cryptography using @noble libraries
- 📘 TypeScript-first design with strong typing
- 🦕 Deno-native with Web API compatibility

## Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/mls-ts.git
cd mls-ts

# Run tests
deno test --allow-all

# Run example
deno run --allow-all examples/basic-example.ts
```

## Usage Example (Current Capabilities)

```typescript
import { 
  CipherSuite, 
  createMLSClient, 
  createGroup, 
  joinGroup 
} from "./src/mod.ts";

// Create MLS clients
const alice = await createMLSClient("alice@example.com");
const bob = await createMLSClient("bob@example.com");

// Choose cipher suite
const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

// Generate KeyPackages
const aliceKeyPackage = await alice.generateKeyPackage(suite);
const bobKeyPackage = await bob.generateKeyPackage(suite);

// Alice creates a new group
const groupId = new TextEncoder().encode("my-secure-group");
const aliceGroup = await createGroup(
  groupId, 
  suite, 
  new TextEncoder().encode("alice@example.com"),
  alice.storage
);

// Alice adds Bob to the group
const addProposal = aliceGroup.addMember(bobKeyPackage);
const { commit, welcome } = await aliceGroup.commit([addProposal]);

// Bob joins from the Welcome message
const bobGroup = await joinGroup(
  welcome!,
  [bobKeyPackage],
  bob.storage  
);

// Send encrypted messages
const message = new TextEncoder().encode("Hello, secure group!");
const encryptedMessage = await aliceGroup.encryptMessage(message);

// Bob decrypts the message
const decrypted = await bobGroup.decryptMessage(encryptedMessage);
console.log(new TextDecoder().decode(decrypted)); // "Hello, secure group!"

// Group operations
const members = aliceGroup.getMembers();
const currentEpoch = aliceGroup.getEpoch();
console.log(`Group has ${members.length} members at epoch ${currentEpoch}`);

// Propose and commit member updates
const updateProposal = aliceGroup.update(); // Alice updates her key
await aliceGroup.commit([updateProposal]); // Post-compromise security

// Group resumption/branching
import { resumeGroup, ResumptionPSKUsage } from "./src/group.ts";

const resumedGroup = await resumeGroup(
  aliceGroup,
  new TextEncoder().encode("resumed-group"), 
  [0, 1], // Leaf indices to include
  ResumptionPSKUsage.APPLICATION,
  alice.storage
);
```

## Documentation

- [Implementation Status](./implementation.md) - Current progress and
  architecture
- [Security Analysis](./SECURITY_ANALYSIS.md) - Detailed security assessment
- [Roadmap](./ROADMAP.md) - Development priorities and timeline
- [Design Decisions](./DESIGN.md) - Key architectural choices
- [Known Issues](./KNOWN_ISSUES.md) - Current limitations and gotchas

## Development

This is an active research project. Contributors should:

1. Read the security analysis before making changes
2. Follow the design principles in DESIGN.md
3. Add tests for all new functionality
4. Update documentation as needed

## Dependencies

- `@noble/hashes` - SHA2 hash functions and HMAC
- `@noble/curves` - Elliptic curve operations
- `@noble/ciphers` - AES-GCM and ChaCha20Poly1305
- No other external dependencies

## License

MIT

## Disclaimer

This software is provided as-is for research and educational purposes. It has
not been audited and should not be used for any production or sensitive
applications.
