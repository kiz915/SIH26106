const { expect } = require("chai");
const { ethers } = require("hardhat");
const crypto = require("crypto");

// SHA-256 hash function to match Python backend implementation
function sha256Hash(data) {
  return "0x" + crypto.createHash('sha256').update(data).digest('hex');
}

describe("EvidenceRegistry", function () {
  let evidenceRegistry;
  let owner;
  let addr1;
  let addr2;
  
  // Sample evidence data
  const evidenceId1 = "EVID-20260907-ABC12345";
  const evidenceId2 = "EVID-20260907-XYZ67890";
  const evidenceHash1 = sha256Hash(Buffer.from("forensic_report_1", 'utf8'));
  const evidenceHash2 = sha256Hash(Buffer.from("forensic_report_2", 'utf8'));
  const tamperedHash = sha256Hash(Buffer.from("tampered_report", 'utf8'));
  const stage1 = "FORENSIC_ANALYSIS";
  const stage2 = "REPORT_GENERATED";

  beforeEach(async function () {
    [owner, addr1, addr2] = await ethers.getSigners();
    
    const EvidenceRegistry = await ethers.getContractFactory("EvidenceRegistry");
    evidenceRegistry = await EvidenceRegistry.deploy();
    await evidenceRegistry.waitForDeployment();
  });

  describe("Contract Deployment", function () {
    it("Should deploy the contract successfully", async function () {
      const contractAddress = await evidenceRegistry.getAddress();
      expect(contractAddress).to.properAddress;
    });

    it("Should start with zero evidence count", async function () {
      const count = await evidenceRegistry.getEvidenceCount();
      expect(count).to.equal(0);
    });
  });

  describe("Evidence Registration", function () {
    it("Should register evidence successfully", async function () {
      const tx = await evidenceRegistry.registerEvidence(evidenceId1, evidenceHash1, stage1);
      const receipt = await tx.wait();
      
      // Check that evidence exists
      const exists = await evidenceRegistry.evidenceRecordExists(evidenceId1);
      expect(exists).to.be.true;
      
      // Check evidence count
      const count = await evidenceRegistry.getEvidenceCount();
      expect(count).to.equal(1);
    });

    it("Should emit EvidenceRegistered event", async function () {
      const tx = await evidenceRegistry.registerEvidence(evidenceId1, evidenceHash1, stage1);
      const receipt = await tx.wait();
      
      const event = receipt.logs.find(log => {
        try {
          const parsed = evidenceRegistry.interface.parseLog(log);
          return parsed.name === "EvidenceRegistered";
        } catch (e) {
          return false;
        }
      });
      
      expect(event).to.not.be.undefined;
    });

    it("Should fail to register evidence with empty ID", async function () {
      await expect(
        evidenceRegistry.registerEvidence("", evidenceHash1, stage1)
      ).to.be.revertedWith("Evidence ID cannot be empty");
    });

    it("Should fail to register evidence with zero hash", async function () {
      await expect(
        evidenceRegistry.registerEvidence(evidenceId1, ethers.ZeroHash, stage1)
      ).to.be.revertedWith("Evidence hash cannot be zero");
    });

    it("Should fail to register duplicate evidence", async function () {
      await evidenceRegistry.registerEvidence(evidenceId1, evidenceHash1, stage1);
      
      await expect(
        evidenceRegistry.registerEvidence(evidenceId1, evidenceHash2, stage2)
      ).to.be.revertedWith("Evidence already registered");
    });

    it("Should allow different addresses to register evidence", async function () {
      await evidenceRegistry.connect(addr1).registerEvidence(evidenceId1, evidenceHash1, stage1);
      await evidenceRegistry.connect(addr2).registerEvidence(evidenceId2, evidenceHash2, stage2);
      
      const count = await evidenceRegistry.getEvidenceCount();
      expect(count).to.equal(2);
    });
  });

  describe("Evidence Retrieval", function () {
    beforeEach(async function () {
      await evidenceRegistry.registerEvidence(evidenceId1, evidenceHash1, stage1);
    });

    it("Should retrieve evidence by ID", async function () {
      const evidence = await evidenceRegistry.getEvidence(evidenceId1);
      
      expect(evidence[0]).to.equal(evidenceHash1); // evidenceHash
      expect(evidence[2]).to.equal(stage1);        // stage
      expect(evidence[3]).to.equal(owner.address); // submitter
    });

    it("Should return valid timestamp", async function () {
      const evidence = await evidenceRegistry.getEvidence(evidenceId1);
      const timestamp = evidence[1];
      
      expect(timestamp).to.be.gt(0);
      expect(timestamp).to.be.lte(Math.floor(Date.now() / 1000) + 100); // Allow some margin
    });

    it("Should fail to retrieve non-existent evidence", async function () {
      await expect(
        evidenceRegistry.getEvidence("NON_EXISTENT_ID")
      ).to.be.revertedWith("Evidence does not exist");
    });

    it("Should get evidence hash only", async function () {
      const hash = await evidenceRegistry.getEvidenceHash(evidenceId1);
      expect(hash).to.equal(evidenceHash1);
    });
  });

  describe("Evidence Verification", function () {
    beforeEach(async function () {
      await evidenceRegistry.registerEvidence(evidenceId1, evidenceHash1, stage1);
    });

    it("Should verify correct hash successfully", async function () {
      const tx = await evidenceRegistry.verifyEvidence(evidenceId1, evidenceHash1);
      const receipt = await tx.wait();
      
      const event = receipt.logs.find(log => {
        try {
          const parsed = evidenceRegistry.interface.parseLog(log);
          return parsed.name === "EvidenceVerified";
        } catch (e) {
          return false;
        }
      });
      
      expect(event).to.not.be.undefined;
      const parsed = evidenceRegistry.interface.parseLog(event);
      expect(parsed.args.verified).to.be.true;
    });

    it("Should detect tampered evidence", async function () {
      const tx = await evidenceRegistry.verifyEvidence(evidenceId1, tamperedHash);
      const receipt = await tx.wait();
      
      const event = receipt.logs.find(log => {
        try {
          const parsed = evidenceRegistry.interface.parseLog(log);
          return parsed.name === "EvidenceVerified";
        } catch (e) {
          return false;
        }
      });
      
      expect(event).to.not.be.undefined;
      const parsed = evidenceRegistry.interface.parseLog(event);
      expect(parsed.args.verified).to.be.false;
    });

    it("Should emit EvidenceVerified event", async function () {
      const tx = await evidenceRegistry.verifyEvidence(evidenceId1, evidenceHash1);
      const receipt = await tx.wait();
      
      const event = receipt.logs.find(log => {
        try {
          const parsed = evidenceRegistry.interface.parseLog(log);
          return parsed.name === "EvidenceVerified";
        } catch (e) {
          return false;
        }
      });
      
      expect(event).to.not.be.undefined;
    });

    it("Should fail to verify non-existent evidence", async function () {
      await expect(
        evidenceRegistry.verifyEvidence("NON_EXISTENT_ID", evidenceHash1)
      ).to.be.revertedWith("Evidence does not exist");
    });
  });

  describe("Evidence Existence Checking", function () {
    it("Should return false for non-existent evidence", async function () {
      const exists = await evidenceRegistry.evidenceRecordExists(evidenceId1);
      expect(exists).to.be.false;
    });

    it("Should return true for registered evidence", async function () {
      await evidenceRegistry.registerEvidence(evidenceId1, evidenceHash1, stage1);
      
      const exists = await evidenceRegistry.evidenceRecordExists(evidenceId1);
      expect(exists).to.be.true;
    });
  });

  describe("Multiple Evidence Records", function () {
    beforeEach(async function () {
      await evidenceRegistry.registerEvidence(evidenceId1, evidenceHash1, stage1);
      await evidenceRegistry.registerEvidence(evidenceId2, evidenceHash2, stage2);
    });

    it("Should maintain correct evidence count", async function () {
      const count = await evidenceRegistry.getEvidenceCount();
      expect(count).to.equal(2);
    });

    it("Should retrieve evidence by index", async function () {
      const id1 = await evidenceRegistry.getEvidenceIdByIndex(0);
      const id2 = await evidenceRegistry.getEvidenceIdByIndex(1);
      
      expect(id1).to.equal(evidenceId1);
      expect(id2).to.equal(evidenceId2);
    });

    it("Should fail to retrieve evidence with invalid index", async function () {
      await expect(
        evidenceRegistry.getEvidenceIdByIndex(10)
      ).to.be.revertedWith("Index out of bounds");
    });

    it("Should get all evidence IDs", async function () {
      const allIds = await evidenceRegistry.getAllEvidenceIds();
      
      expect(allIds.length).to.equal(2);
      expect(allIds[0]).to.equal(evidenceId1);
      expect(allIds[1]).to.equal(evidenceId2);
    });
  });

  describe("Chain of Custody - Stage Updates", function () {
    beforeEach(async function () {
      await evidenceRegistry.registerEvidence(evidenceId1, evidenceHash1, stage1);
    });

    it("Should update evidence stage", async function () {
      await evidenceRegistry.updateEvidenceStage(evidenceId1, stage2);
      
      const evidence = await evidenceRegistry.getEvidence(evidenceId1);
      expect(evidence[2]).to.equal(stage2); // updated stage
    });

    it("Should fail to update stage with empty string", async function () {
      await expect(
        evidenceRegistry.updateEvidenceStage(evidenceId1, "")
      ).to.be.revertedWith("Stage cannot be empty");
    });

    it("Should fail to update stage by non-submitter", async function () {
      await evidenceRegistry.registerEvidence(evidenceId2, evidenceHash2, stage1);
      
      await expect(
        evidenceRegistry.connect(addr1).updateEvidenceStage(evidenceId2, stage2)
      ).to.be.revertedWith("Only submitter can update stage");
    });

    it("Should fail to update stage for non-existent evidence", async function () {
      await expect(
        evidenceRegistry.updateEvidenceStage("NON_EXISTENT_ID", stage2)
      ).to.be.revertedWith("Evidence does not exist");
    });
  });

  describe("Submitter Information", function () {
    it("Should record submitter address correctly", async function () {
      await evidenceRegistry.connect(addr1).registerEvidence(evidenceId1, evidenceHash1, stage1);
      
      const evidence = await evidenceRegistry.getEvidence(evidenceId1);
      expect(evidence[3]).to.equal(addr1.address); // submitter
    });

    it("Should allow multiple submitters", async function () {
      await evidenceRegistry.connect(addr1).registerEvidence(evidenceId1, evidenceHash1, stage1);
      await evidenceRegistry.connect(addr2).registerEvidence(evidenceId2, evidenceHash2, stage2);
      
      const evidence1 = await evidenceRegistry.getEvidence(evidenceId1);
      const evidence2 = await evidenceRegistry.getEvidence(evidenceId2);
      
      expect(evidence1[3]).to.equal(addr1.address);
      expect(evidence2[3]).to.equal(addr2.address);
    });
  });

  describe("Timestamp Recording", function () {
    it("Should record timestamp at registration", async function () {
      const blockBefore = await ethers.provider.getBlock("latest");
      await evidenceRegistry.registerEvidence(evidenceId1, evidenceHash1, stage1);
      const blockAfter = await ethers.provider.getBlock("latest");
      
      const evidence = await evidenceRegistry.getEvidence(evidenceId1);
      const timestamp = evidence[1];
      
      expect(timestamp).to.be.gte(blockBefore.timestamp);
      expect(timestamp).to.be.lte(blockAfter.timestamp);
    });

    it("Should record verification timestamp in event", async function () {
      await evidenceRegistry.registerEvidence(evidenceId1, evidenceHash1, stage1);
      
      const tx = await evidenceRegistry.verifyEvidence(evidenceId1, evidenceHash1);
      const receipt = await tx.wait();
      
      const event = receipt.logs.find(log => {
        try {
          const parsed = evidenceRegistry.interface.parseLog(log);
          return parsed.name === "EvidenceVerified";
        } catch (e) {
          return false;
        }
      });
      
      expect(event).to.not.be.undefined;
    });
  });

  describe("Invalid Evidence Operations", function () {
    it("Should handle non-existent evidence gracefully", async function () {
      const exists = await evidenceRegistry.evidenceRecordExists("FAKE_ID");
      expect(exists).to.be.false;
    });

    it("Should not allow operations on non-existent evidence", async function () {
      await expect(
        evidenceRegistry.getEvidence("FAKE_ID")
      ).to.be.revertedWith("Evidence does not exist");
      
      await expect(
        evidenceRegistry.verifyEvidence("FAKE_ID", evidenceHash1)
      ).to.be.revertedWith("Evidence does not exist");
      
      await expect(
        evidenceRegistry.updateEvidenceStage("FAKE_ID", stage1)
      ).to.be.revertedWith("Evidence does not exist");
    });
  });

  describe("Hash Consistency", function () {
    it("Should maintain consistent hash after registration", async function () {
      await evidenceRegistry.registerEvidence(evidenceId1, evidenceHash1, stage1);
      
      const retrievedHash = await evidenceRegistry.getEvidenceHash(evidenceId1);
      expect(retrievedHash).to.equal(evidenceHash1);
    });

    it("Should detect hash mismatch in verification", async function () {
      await evidenceRegistry.registerEvidence(evidenceId1, evidenceHash1, stage1);
      
      const tx1 = await evidenceRegistry.verifyEvidence(evidenceId1, evidenceHash1);
      const receipt1 = await tx1.wait();
      
      const event1 = receipt1.logs.find(log => {
        try {
          const parsed = evidenceRegistry.interface.parseLog(log);
          return parsed.name === "EvidenceVerified";
        } catch (e) {
          return false;
        }
      });
      
      expect(event1).to.not.be.undefined;
      const parsed1 = evidenceRegistry.interface.parseLog(event1);
      expect(parsed1.args.verified).to.be.true;
      
      const tx2 = await evidenceRegistry.verifyEvidence(evidenceId1, tamperedHash);
      const receipt2 = await tx2.wait();
      
      const event2 = receipt2.logs.find(log => {
        try {
          const parsed = evidenceRegistry.interface.parseLog(log);
          return parsed.name === "EvidenceVerified";
        } catch (e) {
          return false;
        }
      });
      
      expect(event2).to.not.be.undefined;
      const parsed2 = evidenceRegistry.interface.parseLog(event2);
      expect(parsed2.args.verified).to.be.false;
    });
  });
});
