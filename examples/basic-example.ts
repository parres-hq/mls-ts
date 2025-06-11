/**
 * Simple example demonstrating MLS usage with the new Client API
 */

import { CipherSuite, createMLSClient } from "../src/mod.ts";

// Main example
console.log("MLS Library Example - Using Client API");
console.log("=====================================\n");

// Create clients for Alice and Bob
console.log("Creating MLS clients...");

const alice = await createMLSClient("alice@example.com");
const bob = await createMLSClient("bob@example.com");

console.log("✓ Alice's client created");
console.log("✓ Bob's client created\n");

// Generate KeyPackages
console.log("Generating KeyPackages...");

const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

const aliceKeyPackage = await alice.generateKeyPackage(suite);
const bobKeyPackage = await bob.generateKeyPackage(suite);

console.log("✓ Alice's KeyPackage generated");
console.log(`  - Cipher Suite: ${suite}`);
console.log(`  - Init Key Length: ${aliceKeyPackage.initKey.length} bytes`);
console.log(
  `  - Signature Key Length: ${aliceKeyPackage.leafNode.signatureKey.length} bytes`,
);

console.log("\n✓ Bob's KeyPackage generated");
console.log(`  - Cipher Suite: ${suite}`);
console.log(`  - Init Key Length: ${bobKeyPackage.initKey.length} bytes`);
console.log(
  `  - Signature Key Length: ${bobKeyPackage.leafNode.signatureKey.length} bytes`,
);

// Check stored KeyPackages
console.log("\nChecking stored KeyPackages...");

const alicePackages = await alice.getValidKeyPackages();
const bobPackages = await bob.getValidKeyPackages();

console.log(`✓ Alice has ${alicePackages.length} valid KeyPackage(s)`);
console.log(`✓ Bob has ${bobPackages.length} valid KeyPackage(s)`);

// Generate KeyPackages for all supported cipher suites
console.log("\nGenerating KeyPackages for all supported cipher suites...");

const aliceAllPackages = await alice.generateKeyPackagesForAllSuites();
console.log(
  `✓ Alice generated ${aliceAllPackages.length} KeyPackages for different cipher suites:`,
);
for (const pkg of aliceAllPackages) {
  console.log(`  - Cipher Suite: ${pkg.cipherSuite}`);
}

console.log(
  "\nNote: This example demonstrates the Client API for KeyPackage management.",
);
console.log(
  "Next steps will include group creation, member addition, and message encryption.",
);
