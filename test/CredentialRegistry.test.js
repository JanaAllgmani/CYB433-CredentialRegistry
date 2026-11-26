const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture, time } = require("@nomicfoundation/hardhat-network-helpers");

async function deployRegistryFixture() {
    const [admin, issuer, issuer2, user] = await ethers.getSigners();

    const CredentialRegistry = await ethers.getContractFactory("CredentialRegistry");
    const registry = await CredentialRegistry.deploy();

    await registry.waitForDeployment();

    return { registry, admin, issuer, issuer2, user };
}

describe("CredentialRegistry", function () {

    // Test 01: Admin role
    it("Should assign admin role to the deployer", async function () {
        const { registry, admin } = await loadFixture(deployRegistryFixture);

        const adminRole = await registry.DEFAULT_ADMIN_ROLE();

        expect(await registry.hasRole(adminRole, admin.address)).to.equal(true);
    });

    // Test 02: Add issuer
    it("Should allow admin to add an issuer", async function () {
        const { registry, admin, issuer } = await loadFixture(deployRegistryFixture);

        await expect(registry.connect(admin).addIssuer(issuer.address))
            .to.emit(registry, "IssuerAdded")
            .withArgs(issuer.address);

        const issuerRole = await registry.ISSUER_ROLE();

        expect(await registry.hasRole(issuerRole, issuer.address)).to.equal(true);
    });

    // Test 03: Remove issuer
    it("Should allow admin to remove an issuer", async function () {
        const { registry, admin, issuer } = await loadFixture(deployRegistryFixture);

        await registry.connect(admin).addIssuer(issuer.address);

        await expect(registry.connect(admin).removeIssuer(issuer.address))
            .to.emit(registry, "IssuerRemoved")
            .withArgs(issuer.address);

        const issuerRole = await registry.ISSUER_ROLE();

        expect(await registry.hasRole(issuerRole, issuer.address)).to.equal(false);
    });

    // Test 04: Invalid issuer address
    it("Should reject zero address as an issuer", async function () {
        const { registry, admin } = await loadFixture(deployRegistryFixture);

        await expect(
            registry.connect(admin).addIssuer(ethers.ZeroAddress)
        ).to.be.revertedWith("Invalid address");
    });

    // Test 05: Duplicate issuer
    it("Should reject duplicate issuers", async function () {
        const { registry, admin, issuer } = await loadFixture(deployRegistryFixture);

        await registry.connect(admin).addIssuer(issuer.address);

        await expect(
            registry.connect(admin).addIssuer(issuer.address)
        ).to.be.revertedWith("Already an issuer");
    });

    // Test 06: Remove unregistered issuer
    it("Should reject removing an unregistered issuer", async function () {
        const { registry, admin, issuer } = await loadFixture(deployRegistryFixture);

        await expect(
            registry.connect(admin).removeIssuer(issuer.address)
        ).to.be.revertedWith("Not an issuer");
    });

    
    // Test 07: Administrative access control
it("Should restrict administrative operations to admins", async function () {
    const { registry, issuer, user } = await loadFixture(deployRegistryFixture);

    const adminRole = await registry.DEFAULT_ADMIN_ROLE();

    await expect(registry.connect(user).addIssuer(issuer.address))
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(user.address, adminRole);

    await expect(registry.connect(user).removeIssuer(issuer.address))
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(user.address, adminRole);

    await expect(registry.connect(user).pause())
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(user.address, adminRole);

    await expect(registry.connect(user).unpause())
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(user.address, adminRole);
});
    // Test 08: Issue credential
    it("Should issue and store a credential correctly", async function () {
        const { registry, admin, issuer } = await loadFixture(deployRegistryFixture);

        await registry.connect(admin).addIssuer(issuer.address);

        const credentialHash = ethers.id("Academic Credential 01");

        await expect(
            registry.connect(issuer).issueCredential(credentialHash, 0)
        ).to.emit(registry, "CredentialIssued");

        const credential = await registry.getCredential(credentialHash);

        expect(credential.issuer).to.equal(issuer.address);
        expect(credential.status).to.equal(1n);
        expect(credential.expiresAt).to.equal(0n);
        expect(credential.issuedAt).to.be.greaterThan(0n);
        expect(await registry.issuedCount(issuer.address)).to.equal(1n);
    });

    // Test 09: Duplicate credential
    it("Should reject duplicate credentials", async function () {
        const { registry, admin, issuer } = await loadFixture(deployRegistryFixture);

        await registry.connect(admin).addIssuer(issuer.address);

        const credentialHash = ethers.id("Academic Credential 02");

        await registry.connect(issuer).issueCredential(credentialHash, 0);

        await expect(
            registry.connect(issuer).issueCredential(credentialHash, 0)
        ).to.be.revertedWithCustomError(
            registry, "CredentialAlreadyExists"
        ).withArgs(credentialHash);
    });

    // Test 10: Zero hash
    it("Should reject a zero credential hash", async function () {
        const { registry, admin, issuer } = await loadFixture(deployRegistryFixture);

        await registry.connect(admin).addIssuer(issuer.address);

        await expect(
            registry.connect(issuer).issueCredential(ethers.ZeroHash, 0)
        ).to.be.revertedWithCustomError(registry, "ZeroHash");
    });

    // Test 11: Invalid expiry date
    it("Should reject an invalid expiry date", async function () {
        const { registry, admin, issuer } = await loadFixture(deployRegistryFixture);

        await registry.connect(admin).addIssuer(issuer.address);

        const credentialHash = ethers.id("Academic Credential 03");
        const pastTime = (await time.latest()) - 100;

        await expect(
            registry.connect(issuer).issueCredential(credentialHash, pastTime)
        ).to.be.revertedWithCustomError(
            registry, "InvalidExpiry"
        ).withArgs(pastTime);
    });

   // Test 12: Issuer authorization
it("Should reject credential issuance by unauthorized users", async function () {
    const { registry, user } = await loadFixture(deployRegistryFixture);

    const issuerRole = await registry.ISSUER_ROLE();
    const credentialHash = ethers.id("Unauthorized Credential");

    await expect(
        registry.connect(user).issueCredential(credentialHash, 0)
    ).to.be.revertedWithCustomError(
        registry, "AccessControlUnauthorizedAccount"
    ).withArgs(user.address, issuerRole);
});

    // Test 13: Verify credentials
    it("Should verify active and nonexistent credentials correctly", async function () {
        const { registry, admin, issuer, user } = await loadFixture(deployRegistryFixture);

        await registry.connect(admin).addIssuer(issuer.address);

        const credentialHash = ethers.id("Academic Credential 04");
        const unknownHash = ethers.id("Unknown Credential");

        await registry.connect(issuer).issueCredential(credentialHash, 0);

        const valid = await registry.connect(user).verifyCredential(credentialHash);

        expect(valid.isValid).to.equal(true);
        expect(valid.status).to.equal(1n);
        expect(valid.issuer).to.equal(issuer.address);

        const unknown = await registry.verifyCredential(unknownHash);

        expect(unknown.isValid).to.equal(false);
        expect(unknown.status).to.equal(0n);

        await expect(
            registry.getCredential(unknownHash)
        ).to.be.revertedWithCustomError(
            registry, "CredentialNotFound"
        ).withArgs(unknownHash);
    });

    // Test 14: Revoke credential
    it("Should revoke a credential and update its status", async function () {
        const { registry, admin, issuer } = await loadFixture(deployRegistryFixture);

        await registry.connect(admin).addIssuer(issuer.address);

        const credentialHash = ethers.id("Academic Credential 05");
        const reasonHash = ethers.id("Credential withdrawn");

        await registry.connect(issuer).issueCredential(credentialHash, 0);

        await expect(
            registry.connect(issuer).revokeCredential(credentialHash, reasonHash)
        ).to.emit(registry, "CredentialRevoked")
            .withArgs(credentialHash, issuer.address, reasonHash);

        const result = await registry.verifyCredential(credentialHash);

        expect(result.isValid).to.equal(false);
        expect(result.status).to.equal(2n);
    });

    // Test 15: Invalid revocation
    it("Should reject invalid credential revocation", async function () {
        const { registry, admin, issuer } = await loadFixture(deployRegistryFixture);

        await registry.connect(admin).addIssuer(issuer.address);

        const credentialHash = ethers.id("Academic Credential 06");
        const unknownHash = ethers.id("Missing Credential");
        const reasonHash = ethers.id("Revocation reason");

        await expect(
            registry.connect(issuer).revokeCredential(unknownHash, reasonHash)
        ).to.be.revertedWithCustomError(
            registry, "CredentialNotFound"
        ).withArgs(unknownHash);

        await registry.connect(issuer).issueCredential(credentialHash, 0);
        await registry.connect(issuer).revokeCredential(credentialHash, reasonHash);

        await expect(
            registry.connect(issuer).revokeCredential(credentialHash, reasonHash)
        ).to.be.revertedWithCustomError(
            registry, "CredentialNotActive"
        ).withArgs(credentialHash);
    });

    // Test 16: Credential expiration
    it("Should detect expired credentials", async function () {
        const { registry, admin, issuer } = await loadFixture(deployRegistryFixture);

        await registry.connect(admin).addIssuer(issuer.address);

        const credentialHash = ethers.id("Academic Credential 07");
        const expiry = (await time.latest()) + 3600;

        await registry.connect(issuer).issueCredential(credentialHash, expiry);

        const beforeExpiry = await registry.verifyCredential(credentialHash);

        expect(beforeExpiry.isValid).to.equal(true);
        expect(beforeExpiry.status).to.equal(1n);

        await time.increase(3601);

        const afterExpiry = await registry.verifyCredential(credentialHash);

        expect(afterExpiry.isValid).to.equal(false);
        expect(afterExpiry.status).to.equal(3n);
    });

    // Test 17: Pause and unpause
    
it("Should enforce pause and resume operations", async function () {
    const { registry, admin, issuer } = await loadFixture(deployRegistryFixture);

    await registry.connect(admin).addIssuer(issuer.address);

    const hash = ethers.id("Credential 17");
    const newHash = ethers.id("New Credential 17");
    const reason = ethers.id("Revocation reason");

    await registry.connect(issuer).issueCredential(hash, 0);

    await expect(registry.connect(admin).pause())
        .to.emit(registry, "Paused");

    expect(await registry.paused()).to.equal(true);

    await expect(
        registry.connect(issuer).issueCredential(newHash, 0)
    ).to.be.revertedWithCustomError(registry, "EnforcedPause");

    await expect(
        registry.connect(issuer).revokeCredential(hash, reason)
    ).to.be.revertedWithCustomError(registry, "EnforcedPause");

    await expect(registry.connect(admin).unpause())
        .to.emit(registry, "Unpaused");

    expect(await registry.paused()).to.equal(false);

    await expect(
        registry.connect(issuer).issueCredential(newHash, 0)
    ).to.emit(registry, "CredentialIssued");
});

});