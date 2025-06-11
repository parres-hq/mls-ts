/**
 * Test case for MLS Client implementation
 */

import {
  assertEquals,
  assertExists,
} from "https://deno.land/std@0.218.0/assert/mod.ts";
import {
  CipherSuite,
  createMLSClient,
  CredentialType,
  LeafNodeSource,
  MLS_VERSION,
  MLSClient,
} from "../src/mod.ts";

Deno.test("MLSClient - Create client and generate KeyPackage", async () => {
  // Create a client
  const client = await createMLSClient("alice@example.com");

  // Verify client properties
  const identity = client.getIdentity();
  assertEquals(new TextDecoder().decode(identity), "alice@example.com");

  // Check capabilities
  const capabilities = client.getCapabilities();
  assertExists(capabilities.versions);
  assertExists(capabilities.cipherSuites);
  assertEquals(capabilities.versions.includes(MLS_VERSION), true);

  // Generate a KeyPackage
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const keyPackage = await client.generateKeyPackage(suite);

  // Verify KeyPackage structure
  assertExists(keyPackage);
  assertEquals(keyPackage.protocolVersion, MLS_VERSION);
  assertEquals(keyPackage.cipherSuite, suite);
  assertExists(keyPackage.initKey);
  assertExists(keyPackage.leafNode);
  assertExists(keyPackage.signature);

  // Verify LeafNode
  const leafNode = keyPackage.leafNode;
  assertExists(leafNode.encryptionKey);
  assertExists(leafNode.signatureKey);
  assertExists(leafNode.credential);
  assertEquals(leafNode.credential.credentialType, CredentialType.BASIC);
  assertEquals(
    new TextDecoder().decode(leafNode.credential.identity!),
    "alice@example.com",
  );
  assertEquals(leafNode.leafNodeSource, LeafNodeSource.KEY_PACKAGE);
  assertExists(leafNode.lifetime);
  assertExists(leafNode.signature);

  // Verify we can retrieve the stored KeyPackage
  const validPackages = await client.getValidKeyPackages();
  assertEquals(validPackages.length, 1);
  assertEquals(validPackages[0].cipherSuite, suite);
});

Deno.test("MLSClient - Generate multiple KeyPackages for different cipher suites", async () => {
  const client = new MLSClient({
    identity: new TextEncoder().encode("bob@example.com"),
    supportedCipherSuites: [
      CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
      CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
      CipherSuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    ],
  });

  await client.initialize();

  // Generate KeyPackages for all supported cipher suites
  const packages = await client.generateKeyPackagesForAllSuites();

  // Should have one package per supported suite
  assertEquals(packages.length, 3);

  // Verify each package has the correct cipher suite
  const suites = packages.map((pkg) => pkg.cipherSuite);
  assertEquals(
    suites.includes(CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
    true,
  );
  assertEquals(
    suites.includes(CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
    true,
  );
  assertEquals(
    suites.includes(
      CipherSuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    ),
    true,
  );
});

Deno.test("MLSClient - KeyPackage lifetime validation", async () => {
  const client = new MLSClient({
    identity: new TextEncoder().encode("charlie@example.com"),
    lifetimeInSeconds: 60, // 1 minute for testing
  });

  await client.initialize();

  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const keyPackage = await client.generateKeyPackage(suite);

  // Verify lifetime
  const lifetime = keyPackage.leafNode.lifetime!;
  const now = BigInt(Math.floor(Date.now() / 1000));

  // Should be valid now
  assertEquals(lifetime.notBefore <= now, true);
  assertEquals(lifetime.notAfter > now, true);

  // Should expire in about 60 seconds
  const expectedExpiry = now + BigInt(60);
  assertEquals(lifetime.notAfter <= expectedExpiry + BigInt(5), true); // Allow 5 second buffer
  assertEquals(lifetime.notAfter >= expectedExpiry - BigInt(5), true);
});

Deno.test("MLSClient - Update configuration", async () => {
  const client = new MLSClient({
    identity: new TextEncoder().encode("david@example.com"),
  });

  await client.initialize();

  // Update identity
  client.updateConfiguration({
    identity: new TextEncoder().encode("david.smith@example.com"),
  });

  const newIdentity = client.getIdentity();
  assertEquals(
    new TextDecoder().decode(newIdentity),
    "david.smith@example.com",
  );

  // Generate a KeyPackage with new identity
  const suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  const keyPackage = await client.generateKeyPackage(suite);

  const credential = keyPackage.leafNode.credential;
  assertEquals(
    new TextDecoder().decode(credential.identity!),
    "david.smith@example.com",
  );
});
