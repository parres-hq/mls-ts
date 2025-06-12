# MLS TypeScript/Deno Implementation

A complete TypeScript implementation of the Message Layer Security (MLS)
protocol (RFC 9420) for Deno, focusing on security, performance, and minimal
external dependencies.

## ⚠️ Security Status

This implementation is **NOT ready for production deployment**. A professional
security audit is recommended for high-security environments. See
[SECURITY_ANALYSIS.md](./docs/SECURITY_ANALYSIS.md) for detailed assessment.

## Usage Example

### Complete Group Messaging Flow

```typescript
import { createGroup, createMLSClient, joinFromWelcome } from "./src/mod.ts";
import { CipherSuite } from "./src/types.ts";
import { InMemoryMLSStorage } from "./src/storage-memory.ts";

// Create MLS clients for Alice and Bob
const aliceStorage = new InMemoryMLSStorage();
const bobStorage = new InMemoryMLSStorage();

const alice = await createMLSClient("alice@example.com", aliceStorage);
const bob = await createMLSClient("bob@example.com", bobStorage);

// Choose cipher suite
const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

// Generate KeyPackages
const aliceKeyPackage = await alice.generateKeyPackage(suite);
const bobKeyPackage = await bob.generateKeyPackage(suite);

// Alice creates a new group
const groupId = new TextEncoder().encode("secure-team-chat");
const aliceGroup = await createGroup(
  groupId,
  suite,
  new TextEncoder().encode("alice@example.com"),
  aliceStorage,
);

// Alice adds Bob to the group
const addProposal = await aliceGroup.addMember(bobKeyPackage);
const { commit, welcome } = await aliceGroup.commit();

// Bob joins from the Welcome message
const bobGroup = await joinFromWelcome(
  welcome!,
  [bobKeyPackage],
  bobStorage,
);

// Send encrypted messages
const message = new TextEncoder().encode("Hello secure group! 🔒");
const encryptedMessage = await aliceGroup.encryptMessage(message);

// Bob decrypts the message
const decrypted = await bobGroup.decryptMessage(encryptedMessage);
console.log(new TextDecoder().decode(decrypted)); // "Hello secure group! 🔒"

// Group operations
console.log(`Group has ${aliceGroup.getMembers().length} members`);
console.log(`Current epoch: ${aliceGroup.getEpoch()}`);

// Update keys for post-compromise security
await aliceGroup.update(); // Alice updates her keys
await aliceGroup.commit(); // Advances epoch and rotates group keys
```

### Client & KeyPackage Management

```typescript
import { createMLSClient } from "./src/client.ts";
import { CipherSuite } from "./src/types.ts";

// Create client with automatic storage
const client = await createMLSClient("user@example.com");

// Generate KeyPackages for different cipher suites
const keyPackage1 = await client.generateKeyPackage(
  CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
);

const keyPackage2 = await client.generateKeyPackage(
  CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
);

// Get all valid KeyPackages
const validPackages = await client.getValidKeyPackages();
console.log(`Client has ${validPackages.length} valid KeyPackages`);
```

## Architecture

The implementation follows clean modular architecture:

```
src/
├── types.ts        # Core MLS types and structures (RFC 9420)
├── crypto.ts       # Cryptographic operations using @noble
├── hpke.ts         # Complete HPKE implementation (RFC 9180)
├── encoding.ts     # Wire format handling (TLS-style)
├── ratchet-tree.ts # Binary tree with OpenMLS architecture
├── key-schedule.ts # Key derivation & epoch management
├── client.ts       # Client & KeyPackage management
├── group.ts        # Complete group operations
├── message.ts      # Message framing & encryption
├── storage.ts      # Storage interface
├── storage-memory.ts # In-memory storage backend
└── mod.ts          # Main exports
```

## Dependencies

**Minimal, security-focused dependencies:**

- `@noble/hashes` - SHA2 hash functions and HMAC
- `@noble/curves` - Elliptic curve operations (Ed25519, X25519, P-256/384/521)
- `@noble/ciphers` - AEAD ciphers (AES-GCM, ChaCha20Poly1305)

All dependencies are well-audited, TypeScript-native, and actively maintained.

## Documentation

- [**Implementation Status**](./docs/IMPLEMENTATION.md) - Complete status &
  architecture
- [**Security Analysis**](./docs/SECURITY_ANALYSIS.md) - Detailed security
  assessment
- [**Quick Reference**](./docs/QUICK_REFERENCE.md) - API overview & examples
- [**Design Decisions**](./docs/DESIGN.md) - Key architectural choices
- [**Known Issues**](./docs/KNOWN_ISSUES.md) - Current limitations (mostly
  resolved)
- [**Roadmap**](./docs/ROADMAP.md) - Development priorities & timeline

## Development

### Contributing

This project is still early but has implemented close to complete core
functionality. Contributions welcome in:

- Auditing/Verifying the implementation
- Addition of tests using the RFC 9420 Test vectors
- Addition of fuzz testing
- Performance optimization and benchmarking
- Security analysis and hardening
- Integration testing with other MLS implementations
- Addition of additional MLS extensions and methods

### Development Workflow

```bash
# Format code
deno task fmt

# Lint code
deno task lint

# Pre-commit checks (format, lint, type check, test)
deno task precommit

# Type checking
deno task check

# Development server (auto-reload)
deno task dev
```

## License

MIT

## Security Disclosure

For security issues, please email [j@parres.org] rather than opening public
issues.

## Acknowledgments

This implementation follows RFC 9420 and draws architectural inspiration from:

- [OpenMLS](https://github.com/openmls/openmls) - Rust implementation
- [MLSpp](https://github.com/cisco/mlspp) - C++ implementation
- The MLS Working Group at IETF
