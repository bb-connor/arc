import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";
import ganache from "ganache";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const artifactsDir = path.join(rootDir, "artifacts");
const deploymentsDir = path.join(rootDir, "deployments");
const reportsDir = path.join(rootDir, "reports");

const PORT = 8545;
const RPC_URL = `http://127.0.0.1:${PORT}`;
const CHAIN_ID = 31337;
const USDC_UNITS = 10n ** 6n;

const ACCOUNT_CONFIG = [
  { name: "admin", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000001" },
  { name: "operator", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000002" },
  { name: "delegate", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000003" },
  { name: "beneficiary", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000004" },
  { name: "depositor", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000005" },
  { name: "principal", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000006" },
  { name: "outsider", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000007" },
];

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function artifactPath(name) {
  return path.join(artifactsDir, `${name}.json`);
}

function readArtifact(name) {
  return JSON.parse(fs.readFileSync(artifactPath(name), "utf8"));
}

async function deploy(name, signer, ...args) {
  const artifact = readArtifact(name);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

function toHexBalance(amount) {
  return ethers.toBeHex(amount);
}

async function expectRevert(label, action) {
  let reverted = false;
  let message = "";
  try {
    await action();
  } catch (error) {
    reverted = true;
    message = error?.shortMessage ?? error?.info?.error?.message ?? error?.message ?? String(error);
  }
  assert(reverted, `${label} should revert`);
  return message;
}

function toBytes32Label(label) {
  return ethers.keccak256(ethers.toUtf8Bytes(label));
}

function normalizeBigints(value) {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeBigints(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, normalizeBigints(nested)]),
    );
  }
  return value;
}

function logStep(message) {
  console.log(`[qualify] ${message}`);
}

async function waitForReceipt(provider, txResponse) {
  for (let attempt = 0; attempt < 200; ++attempt) {
    const receipt = await provider.getTransactionReceipt(txResponse.hash);
    if (receipt) {
      return receipt;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`timed out waiting for receipt ${txResponse.hash}`);
}

async function findContractEvent(receipt, contract, eventName) {
  const contractAddress = (await contract.getAddress()).toLowerCase();
  for (const log of receipt.logs ?? []) {
    if (log.address.toLowerCase() !== contractAddress) {
      continue;
    }
    try {
      const parsed = contract.interface.parseLog(log);
      if (parsed?.name === eventName) {
        return parsed;
      }
    } catch {}
  }
  throw new Error(`missing ${eventName} event on receipt ${receipt.hash}`);
}

async function main() {
  ensureDir(deploymentsDir);
  ensureDir(reportsDir);

  const server = ganache.server({
    logging: { quiet: true },
    chain: { chainId: CHAIN_ID, hardfork: "shanghai" },
    wallet: {
      accounts: ACCOUNT_CONFIG.map((account) => ({
        secretKey: account.privateKey,
        balance: toHexBalance(ethers.parseEther("1000")),
      })),
    },
  });

  await new Promise((resolve, reject) => {
    server.listen(PORT, (error) => (error ? reject(error) : resolve()));
  });

  let provider;

  const checks = [];
  const gasEstimates = {};

  try {
    provider = new ethers.JsonRpcProvider(RPC_URL);
    const wallets = Object.fromEntries(
      ACCOUNT_CONFIG.map((account) => {
        const rawWallet = new ethers.Wallet(account.privateKey, provider);
        const signer = new ethers.NonceManager(rawWallet);
        signer.address = rawWallet.address;
        signer.privateKey = account.privateKey;
        return [account.name, signer];
      }),
    );

    const network = await provider.getNetwork();
    const chainId = Number(network.chainId);
    const nowBlock = await provider.getBlock("latest");
    const now = Number(nowBlock.timestamp);

    const operatorEdKeyHash = toBytes32Label("chio-operator-ed25519-key");
    const beneficiaryEntityId = toBytes32Label("chio-beneficiary-entity");
    const priceBase = toBytes32Label("ETH");
    const priceQuote = toBytes32Label("USD");

    logStep("deploying mocks and core contracts");
    const sequencerFeed = await deploy(
      "mocks/MockAggregatorV3",
      wallets.admin,
      0,
      "Base Sequencer Uptime",
      0,
    );
    const ethUsdFeed = await deploy(
      "mocks/MockAggregatorV3",
      wallets.admin,
      8,
      "ETH / USD",
      3000n * 10n ** 8n,
    );
    const mockUsdc = await deploy("mocks/MockERC20", wallets.admin, "Mock USD Coin", "mUSDC", 6);
    const identityRegistry = await deploy(
      "ChioIdentityRegistry",
      wallets.admin,
      wallets.admin.address,
    );
    const rootRegistry = await deploy(
      "ChioRootRegistry",
      wallets.admin,
      await identityRegistry.getAddress(),
    );
    const escrow = await deploy(
      "ChioEscrow",
      wallets.admin,
      await rootRegistry.getAddress(),
      await identityRegistry.getAddress(),
    );
    const bondVault = await deploy(
      "ChioBondVault",
      wallets.admin,
      await rootRegistry.getAddress(),
      await identityRegistry.getAddress(),
    );
    const priceResolver = await deploy(
      "ChioPriceResolver",
      wallets.admin,
      wallets.admin.address,
      await sequencerFeed.getAddress(),
    );

    logStep("registering identity bindings");
    gasEstimates.register_operator = (
      await identityRegistry.registerOperator.estimateGas(
        wallets.operator.address,
        operatorEdKeyHash,
        wallets.operator.address,
        ethers.toUtf8Bytes("binding:operator"),
      )
    ).toString();
    await (
      await identityRegistry.registerOperator(
        wallets.operator.address,
        operatorEdKeyHash,
        wallets.operator.address,
        ethers.toUtf8Bytes("binding:operator"),
      )
    ).wait();
    checks.push({
      id: "identity.operator_registration",
      outcome: "pass",
      note: "Identity registry bound the operator settlement key to the Chio Ed25519 key hash.",
    });

    await (
      await identityRegistry
        .connect(wallets.operator)
        .registerEntity(
          beneficiaryEntityId,
          wallets.beneficiary.address,
          ethers.toUtf8Bytes("binding:beneficiary"),
        )
    ).wait();
    checks.push({
      id: "identity.entity_registration",
      outcome: "pass",
      note: "Operator registered the beneficiary entity binding for settlement parity checks.",
    });

    logStep("authorizing and exercising root publication");
    const delegateExpiry = BigInt(now + 3600);
    gasEstimates.register_delegate = (
      await rootRegistry
        .connect(wallets.operator)
        .registerDelegate.estimateGas(wallets.delegate.address, delegateExpiry)
    ).toString();
    await (
      await rootRegistry
        .connect(wallets.operator)
        .registerDelegate(wallets.delegate.address, delegateExpiry)
    ).wait();
    checks.push({
      id: "anchor.delegate_registration",
      outcome: "pass",
      note: "Root registry accepted a bounded delegate publisher for the operator.",
    });

    await expectRevert("unauthorized root publication", async () => {
      await rootRegistry
        .connect(wallets.outsider)
        .publishRoot(wallets.operator.address, toBytes32Label("unauthorized-root"), 1, 1, 1, 1, operatorEdKeyHash);
    });
    checks.push({
      id: "anchor.unauthorized_publish_denied",
      outcome: "pass",
      note: "Unauthorized publishers revert fail closed.",
    });

    const operatorRoot = toBytes32Label("checkpoint-root-operator");
    gasEstimates.publish_root_operator = (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot.estimateGas(
          wallets.operator.address,
          operatorRoot,
          1,
          1,
          1,
          1,
          operatorEdKeyHash,
        )
    ).toString();
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, operatorRoot, 1, 1, 1, 1, operatorEdKeyHash)
    ).wait();

    const delegateReceiptHash = toBytes32Label("delegate-proof-leaf");
    gasEstimates.publish_root_delegate = (
      await rootRegistry
        .connect(wallets.delegate)
        .publishRoot.estimateGas(
          wallets.operator.address,
          delegateReceiptHash,
          2,
          2,
          2,
          1,
          operatorEdKeyHash,
        )
    ).toString();
    await (
      await rootRegistry
        .connect(wallets.delegate)
        .publishRoot(
          wallets.operator.address,
          delegateReceiptHash,
          2,
          2,
          2,
          1,
          operatorEdKeyHash,
        )
    ).wait();
    checks.push({
      id: "anchor.delegate_publish",
      outcome: "pass",
      note: "Authorized delegate published a root against the operator namespace with canonical publisher traceability.",
    });

    await (await rootRegistry.connect(wallets.operator).revokeDelegate(wallets.delegate.address)).wait();
    await expectRevert("revoked delegate publication", async () => {
      await rootRegistry
        .connect(wallets.delegate)
        .publishRoot(
          wallets.operator.address,
          toBytes32Label("revoked-root"),
          3,
          3,
          3,
          1,
          operatorEdKeyHash,
        );
    });
    checks.push({
      id: "anchor.delegate_revocation",
      outcome: "pass",
      note: "Revoked delegates can no longer publish roots.",
    });

    logStep("configuring token and price feeds");
    await (await mockUsdc.mint(wallets.depositor.address, 5_000_000n * USDC_UNITS)).wait();
    await (await mockUsdc.mint(wallets.principal.address, 5_000_000n * USDC_UNITS)).wait();

    gasEstimates.register_feed = (
      await priceResolver.registerFeed.estimateGas(
        priceBase,
        priceQuote,
        await ethUsdFeed.getAddress(),
        3600,
      )
    ).toString();
    await (
      await priceResolver.registerFeed(
        priceBase,
        priceQuote,
        await ethUsdFeed.getAddress(),
        3600,
      )
    ).wait();

    gasEstimates.price_read = (
      await priceResolver.getPrice.estimateGas(priceBase, priceQuote)
    ).toString();
    const [price, decimals, updatedAt] = await priceResolver.getPrice(priceBase, priceQuote);
    assert.equal(price.toString(), (3000n * 10n ** 8n).toString());
    assert.equal(Number(decimals), 8);
    assert.ok(updatedAt > 0n);
    checks.push({
      id: "oracle.price_read",
      outcome: "pass",
      note: "Price resolver returned the configured feed value under healthy sequencer conditions.",
    });

    await (
      await ethUsdFeed.setRoundData(2, 3000n * 10n ** 8n, BigInt(now - 7200), BigInt(now - 7200), 2)
    ).wait();
    await expectRevert("stale price", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    });
    await (await ethUsdFeed.setAnswer(3000n * 10n ** 8n)).wait();
    await (
      await sequencerFeed.setRoundData(2, 1n, BigInt(now), BigInt(now), 2)
    ).wait();
    await expectRevert("sequencer down", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    });
    await (
      await sequencerFeed.setRoundData(3, 0n, BigInt(now + 1), BigInt(now + 1), 3)
    ).wait();
    checks.push({
      id: "oracle.fail_closed",
      outcome: "pass",
      note: "Price resolver rejects stale feeds and sequencer-down conditions.",
    });

    logStep("exercising escrow lifecycle");
    const escrowTerms = {
      capabilityId: toBytes32Label("capability:devnet"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 1_500_000n,
      deadline: BigInt(now + 7200),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };

    await (
      await mockUsdc.connect(wallets.depositor).approve(await escrow.getAddress(), escrowTerms.maxAmount)
    ).wait();
    logStep("escrow: approved token allowance");
    const escrowId = await escrow.connect(wallets.depositor).deriveEscrowId(escrowTerms);
    gasEstimates.create_escrow = (
      await escrow.connect(wallets.depositor).createEscrow.estimateGas(escrowTerms)
    ).toString();
    logStep("escrow: creating primary escrow");
    const createEscrowTx = await escrow.connect(wallets.depositor).createEscrow(escrowTerms);
    const createEscrowReceipt = await waitForReceipt(provider, createEscrowTx);
    const createdEscrow = await findContractEvent(createEscrowReceipt, escrow, "EscrowCreated");
    assert.equal(createdEscrow.args.escrowId, escrowId);
    logStep("escrow: primary escrow created");

    await expectRevert("proof metadata required", async () => {
      await escrow
        .connect(wallets.beneficiary)
        .releaseWithProof(escrowId, [], delegateReceiptHash, delegateReceiptHash, 100_000n);
    });
    logStep("escrow: under-specified proof path reverted as expected");

    const oneLeafProof = { auditPath: [], leafIndex: 0, treeSize: 1 };
    gasEstimates.merkle_partial_release = (
      await escrow
        .connect(wallets.beneficiary)
        .partialReleaseWithProofDetailed.estimateGas(
          escrowId,
          oneLeafProof,
          delegateReceiptHash,
          delegateReceiptHash,
          500_000n,
        )
    ).toString();
    await (
      await escrow
        .connect(wallets.beneficiary)
        .partialReleaseWithProofDetailed(
          escrowId,
          oneLeafProof,
          delegateReceiptHash,
          delegateReceiptHash,
          500_000n,
        )
    ).wait();
    logStep("escrow: merkle partial release completed");
    checks.push({
      id: "escrow.merkle_partial_release",
      outcome: "pass",
      note: "Escrow accepts the detailed RFC6962 proof path and supports partial settlement.",
    });

    const finalReceiptHash = toBytes32Label("escrow-final-receipt");
    const signatureDigest = ethers.solidityPackedKeccak256(
      ["uint256", "address", "bytes32", "bytes32", "uint256"],
      [chainId, await escrow.getAddress(), escrowId, finalReceiptHash, 1_000_000n],
    );
    const operatorSignature = new ethers.SigningKey(wallets.operator.privateKey).sign(signatureDigest);
    const outsiderSignature = new ethers.SigningKey(wallets.outsider.privateKey).sign(signatureDigest);

    await expectRevert("invalid signature", async () => {
      await escrow
        .connect(wallets.beneficiary)
        .releaseWithSignature(
          escrowId,
          finalReceiptHash,
          1_000_000n,
          outsiderSignature.yParity + 27,
          outsiderSignature.r,
          outsiderSignature.s,
        );
    });
    logStep("escrow: invalid signature rejected");

    logStep("escrow: estimating valid dual-sign release gas");
    gasEstimates.dual_sign_release = (
      await escrow
        .connect(wallets.beneficiary)
        .releaseWithSignature.estimateGas(
          escrowId,
          finalReceiptHash,
          1_000_000n,
          operatorSignature.yParity + 27,
          operatorSignature.r,
          operatorSignature.s,
        )
    ).toString();
    logStep("escrow: validating valid dual-sign release via static call");
    await escrow
      .connect(wallets.beneficiary)
      .releaseWithSignature.staticCall(
        escrowId,
        finalReceiptHash,
        1_000_000n,
        operatorSignature.yParity + 27,
        operatorSignature.r,
        operatorSignature.s,
      );
    logStep("escrow: dual-sign release accepted by static validation");
    checks.push({
      id: "escrow.dual_sign_release",
      outcome: "pass",
      note: "Escrow accepts the operator-bound dual-signature release path and rejects mismatched signers.",
    });

    logStep("escrow: publishing final proof root");
    const finalRootPublishGas = await rootRegistry
      .connect(wallets.operator)
      .publishRoot.estimateGas(
        wallets.operator.address,
        finalReceiptHash,
        3,
        3,
        3,
        1,
        operatorEdKeyHash,
      );
    const finalRootPublishTx = await rootRegistry
      .connect(wallets.operator)
      .publishRoot(
        wallets.operator.address,
        finalReceiptHash,
        3,
        3,
        3,
        1,
        operatorEdKeyHash,
        { gasLimit: (finalRootPublishGas * 12n) / 10n + 50_000n },
      );
    await waitForReceipt(provider, finalRootPublishTx);
    logStep("escrow: root published for final proof release");

    const beneficiaryRpcSigner = await provider.getSigner(wallets.beneficiary.address);
    logStep("escrow: submitting final proof-backed release");
    const finalProofReleaseGas = await escrow
      .connect(beneficiaryRpcSigner)
      .releaseWithProofDetailed.estimateGas(
        escrowId,
        oneLeafProof,
        finalReceiptHash,
        finalReceiptHash,
        1_000_000n,
      );
    const finalProofReleaseTx = await escrow
      .connect(beneficiaryRpcSigner)
      .releaseWithProofDetailed(
        escrowId,
        oneLeafProof,
        finalReceiptHash,
        finalReceiptHash,
        1_000_000n,
        { gasLimit: (finalProofReleaseGas * 12n) / 10n + 50_000n },
      );
    await waitForReceipt(provider, finalProofReleaseTx);
    logStep("escrow: final proof-backed release completed");

    const refundDeadlineBase = Number((await provider.getBlock("latest")).timestamp) + 5;
    const refundTerms = {
      capabilityId: toBytes32Label("capability:refund"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 750_000n,
      deadline: BigInt(refundDeadlineBase),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    await (
      await mockUsdc.connect(wallets.depositor).approve(await escrow.getAddress(), refundTerms.maxAmount)
    ).wait();
    logStep("escrow: approved refund-escrow allowance");
    const refundEscrowId = await escrow.connect(wallets.depositor).deriveEscrowId(refundTerms);
    logStep("escrow: creating refund escrow");
    const refundCreateTx = await escrow.connect(wallets.depositor).createEscrow(refundTerms);
    const refundCreateReceipt = await waitForReceipt(provider, refundCreateTx);
    const refundCreatedEscrow = await findContractEvent(refundCreateReceipt, escrow, "EscrowCreated");
    assert.equal(refundCreatedEscrow.args.escrowId, refundEscrowId);
    logStep("escrow: refund escrow created");
    await expectRevert("refund before expiry", async () => {
      await escrow.refund(refundEscrowId);
    });
    logStep("escrow: premature refund rejected");
    await provider.send("evm_increaseTime", [10]);
    await provider.send("evm_mine", []);
    logStep(`escrow: waiting past refund deadline ${refundTerms.deadline}`);
    const refundRpcSigner = await provider.getSigner(wallets.outsider.address);
    logStep("escrow: submitting refund transaction");
    const refundTx = await escrow
      .connect(refundRpcSigner)
      .refund(refundEscrowId, { gasLimit: 250_000n });
    await waitForReceipt(provider, refundTx);
    logStep("escrow: refund completed");
    checks.push({
      id: "escrow.timeout_refund",
      outcome: "pass",
      note: "Escrow refunds only after expiry and not before.",
    });

    logStep("escrow: qualifying deterministic identity under interleaving and replay");
    const driftEscrowTermsA = {
      capabilityId: toBytes32Label("capability:drift:a"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 210_000n,
      deadline: BigInt(now + 10800),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    const driftEscrowTermsB = {
      capabilityId: toBytes32Label("capability:drift:b"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 220_000n,
      deadline: BigInt(now + 10800),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    await (
      await mockUsdc
        .connect(wallets.depositor)
        .approve(await escrow.getAddress(), driftEscrowTermsA.maxAmount + driftEscrowTermsB.maxAmount)
    ).wait();
    const predictedEscrowA = await escrow.connect(wallets.depositor).deriveEscrowId(driftEscrowTermsA);
    const predictedEscrowB = await escrow.connect(wallets.depositor).deriveEscrowId(driftEscrowTermsB);
    const driftEscrowBTx = await escrow.connect(wallets.depositor).createEscrow(driftEscrowTermsB);
    const driftEscrowBReceipt = await waitForReceipt(provider, driftEscrowBTx);
    const driftEscrowBEvent = await findContractEvent(driftEscrowBReceipt, escrow, "EscrowCreated");
    assert.equal(driftEscrowBEvent.args.escrowId, predictedEscrowB);
    const driftEscrowATx = await escrow.connect(wallets.depositor).createEscrow(driftEscrowTermsA);
    const driftEscrowAReceipt = await waitForReceipt(provider, driftEscrowATx);
    const driftEscrowAEvent = await findContractEvent(driftEscrowAReceipt, escrow, "EscrowCreated");
    assert.equal(driftEscrowAEvent.args.escrowId, predictedEscrowA);
    await expectRevert("duplicate escrow replay", async () => {
      const tx = await escrow.connect(wallets.depositor).createEscrow(driftEscrowTermsA);
      await tx.wait();
    });
    checks.push({
      id: "escrow.identity_reconciliation_under_nonce_drift",
      outcome: "pass",
      note: "Escrow identity remains deterministic under interleaving submissions and duplicate replays fail closed.",
    });

    logStep("exercising bond lifecycle");
    const bondTerms = {
      bondId: toBytes32Label("bond:primary"),
      facilityId: toBytes32Label("facility:primary"),
      principal: wallets.principal.address,
      token: await mockUsdc.getAddress(),
      collateralAmount: 2_000_000n,
      reserveRequirementAmount: 500_000n,
      expiresAt: BigInt(now + 7200),
      reserveRequirementRatioBps: 2500,
      operator: wallets.operator.address,
    };
    await (
      await mockUsdc.connect(wallets.principal).approve(await bondVault.getAddress(), bondTerms.collateralAmount)
    ).wait();
    const bondVaultId = await bondVault.connect(wallets.principal).deriveVaultId(bondTerms);
    gasEstimates.lock_bond = (
      await bondVault.connect(wallets.principal).lockBond.estimateGas(bondTerms)
    ).toString();
    const bondLockTx = await bondVault.connect(wallets.principal).lockBond(bondTerms);
    const bondLockReceipt = await waitForReceipt(provider, bondLockTx);
    const lockedBond = await findContractEvent(bondLockReceipt, bondVault, "BondLocked");
    assert.equal(lockedBond.args.vaultId, bondVaultId);
    const [storedBondTerms, lockedAmount, slashedAmount, released, expired] = await bondVault.getBond(
      bondVaultId,
    );
    assert.equal(storedBondTerms.reserveRequirementAmount, bondTerms.reserveRequirementAmount);
    assert.equal(
      Number(storedBondTerms.reserveRequirementRatioBps),
      bondTerms.reserveRequirementRatioBps,
    );
    assert.equal(lockedAmount, bondTerms.collateralAmount);
    assert.equal(slashedAmount, 0n);
    assert.equal(released, false);
    assert.equal(expired, false);
    checks.push({
      id: "bond.reserve_requirement_metadata_parity",
      outcome: "pass",
      note: "Bond vault locks collateral on-chain while preserving reserve requirement metadata from the signed Chio bond terms for parity and review.",
    });

    await expectRevert("bond proof metadata required", async () => {
      await bondVault
        .connect(wallets.operator)
        .releaseBond(bondVaultId, [], toBytes32Label("bond-root"), toBytes32Label("bond-proof"));
    });

    const bondEvidenceHash = toBytes32Label("bond-release-evidence");
    const bondRootPublishGas = await rootRegistry
      .connect(wallets.operator)
      .publishRoot.estimateGas(
        wallets.operator.address,
        bondEvidenceHash,
        4,
        4,
        4,
        1,
        operatorEdKeyHash,
      );
    const bondRootPublishTx = await rootRegistry
      .connect(wallets.operator)
      .publishRoot(
        wallets.operator.address,
        bondEvidenceHash,
        4,
        4,
        4,
        1,
        operatorEdKeyHash,
        { gasLimit: (bondRootPublishGas * 12n) / 10n + 50_000n },
      );
    await waitForReceipt(provider, bondRootPublishTx);
    gasEstimates.bond_release = (
      await bondVault
        .connect(wallets.operator)
        .releaseBondDetailed.estimateGas(
          bondVaultId,
          oneLeafProof,
          bondEvidenceHash,
          bondEvidenceHash,
        )
    ).toString();
    const bondReleaseTx = await bondVault
      .connect(wallets.operator)
      .releaseBondDetailed(
        bondVaultId,
        oneLeafProof,
        bondEvidenceHash,
        bondEvidenceHash,
        { gasLimit: (BigInt(gasEstimates.bond_release) * 12n) / 10n + 50_000n },
      );
    await waitForReceipt(provider, bondReleaseTx);
    checks.push({
      id: "bond.release_with_proof",
      outcome: "pass",
      note: "Bond vault releases collateral only on the detailed proof path and rejects the under-specified interface.",
    });

    logStep("bond: qualifying deterministic identity under interleaving and replay");
    const driftBondTermsA = {
      bondId: toBytes32Label("bond:drift:a"),
      facilityId: toBytes32Label("facility:drift:a"),
      principal: wallets.principal.address,
      token: await mockUsdc.getAddress(),
      collateralAmount: 1_100_000n,
      reserveRequirementAmount: 275_000n,
      expiresAt: BigInt(now + 10800),
      reserveRequirementRatioBps: 2500,
      operator: wallets.operator.address,
    };
    const driftBondTermsB = {
      bondId: toBytes32Label("bond:drift:b"),
      facilityId: toBytes32Label("facility:drift:b"),
      principal: wallets.principal.address,
      token: await mockUsdc.getAddress(),
      collateralAmount: 1_200_000n,
      reserveRequirementAmount: 300_000n,
      expiresAt: BigInt(now + 10800),
      reserveRequirementRatioBps: 2500,
      operator: wallets.operator.address,
    };
    await (
      await mockUsdc
        .connect(wallets.principal)
        .approve(await bondVault.getAddress(), driftBondTermsA.collateralAmount + driftBondTermsB.collateralAmount)
    ).wait();
    const predictedVaultA = await bondVault.connect(wallets.principal).deriveVaultId(driftBondTermsA);
    const predictedVaultB = await bondVault.connect(wallets.principal).deriveVaultId(driftBondTermsB);
    const driftBondBTx = await bondVault.connect(wallets.principal).lockBond(driftBondTermsB);
    const driftBondBReceipt = await waitForReceipt(provider, driftBondBTx);
    const driftBondBEvent = await findContractEvent(driftBondBReceipt, bondVault, "BondLocked");
    assert.equal(driftBondBEvent.args.vaultId, predictedVaultB);
    const driftBondATx = await bondVault.connect(wallets.principal).lockBond(driftBondTermsA);
    const driftBondAReceipt = await waitForReceipt(provider, driftBondATx);
    const driftBondAEvent = await findContractEvent(driftBondAReceipt, bondVault, "BondLocked");
    assert.equal(driftBondAEvent.args.vaultId, predictedVaultA);
    await expectRevert("duplicate bond replay", async () => {
      const tx = await bondVault.connect(wallets.principal).lockBond(driftBondTermsA);
      await tx.wait();
    });
    checks.push({
      id: "bond.identity_reconciliation_under_nonce_drift",
      outcome: "pass",
      note: "Bond identity remains deterministic under interleaving submissions and duplicate replays fail closed.",
    });

    logStep("writing deployment and qualification reports");
    const localDeployment = {
      manifest_id: "chio.web3-deployment.local-devnet.v1",
      network_name: "Ganache Local Devnet",
      chain_id: `eip155:${chainId}`,
      rpc_url: RPC_URL,
      deployed_at: new Date().toISOString(),
      operator_address: wallets.operator.address,
      delegate_address: wallets.delegate.address,
      settlement_token_symbol: "mUSDC",
      settlement_token_address: await mockUsdc.getAddress(),
      contracts: {
        identity_registry: await identityRegistry.getAddress(),
        root_registry: await rootRegistry.getAddress(),
        escrow: await escrow.getAddress(),
        bond_vault: await bondVault.getAddress(),
        price_resolver: await priceResolver.getAddress(),
      },
      mocks: {
        eth_usd_feed: await ethUsdFeed.getAddress(),
        sequencer_uptime_feed: await sequencerFeed.getAddress(),
      },
    };

    const qualificationReport = {
      report_id: "chio.web3-contract-qualification.local-devnet.v1",
      generated_at: new Date().toISOString(),
      chain_id: `eip155:${chainId}`,
      gas_estimates: gasEstimates,
      checks,
    };

    fs.writeFileSync(
      path.join(deploymentsDir, "local-devnet.json"),
      `${JSON.stringify(normalizeBigints(localDeployment), null, 2)}\n`,
    );
    fs.writeFileSync(
      path.join(reportsDir, "local-devnet-qualification.json"),
      `${JSON.stringify(normalizeBigints(qualificationReport), null, 2)}\n`,
    );

    console.log(
      `Qualified Chio web3 contracts on local devnet at ${RPC_URL}. Reports written to contracts/deployments/local-devnet.json and contracts/reports/local-devnet-qualification.json.`,
    );
  } finally {
    provider?.destroy?.();
    server.close();
  }
}

await main();
