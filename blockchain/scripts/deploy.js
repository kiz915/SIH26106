const hre = require("hardhat");

async function main() {
  console.log("Deploying EvidenceRegistry contract...");

  // Get the contract factory
  const EvidenceRegistry = await hre.ethers.getContractFactory("EvidenceRegistry");

  // Deploy the contract
  const evidenceRegistry = await EvidenceRegistry.deploy();

  // Wait for deployment to complete
  await evidenceRegistry.waitForDeployment();

  const contractAddress = await evidenceRegistry.getAddress();
  
  console.log("EvidenceRegistry deployed to:", contractAddress);
  console.log("Network:", hre.network.name);
  console.log("Transaction hash:", evidenceRegistry.deploymentTransaction().hash);

  // Save deployment info
  const deploymentInfo = {
    network: hre.network.name,
    contractAddress: contractAddress,
    deploymentTransaction: evidenceRegistry.deploymentTransaction().hash,
    deployedAt: new Date().toISOString(),
    chainId: (await hre.ethers.provider.getNetwork()).chainId.toString()
  };

  console.log("\nDeployment Info:", JSON.stringify(deploymentInfo, null, 2));

  // For local development, also save to a file
  if (hre.network.name === "localhost" || hre.network.name === "hardhat") {
    const fs = require("fs");
    const path = require("path");
    const deploymentPath = path.join(__dirname, "..", "deployment.json");
    fs.writeFileSync(deploymentPath, JSON.stringify(deploymentInfo, null, 2));
    console.log(`\nDeployment info saved to: ${deploymentPath}`);
  }

  return contractAddress;
}

// Execute deployment
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
