import { describe, it, expect, beforeEach } from "vitest";
import { ClarityValue, cvToValue, noneCV, ResponseErrorCV, ResponseOkCV, someCV, uintCV } from "@stacks/transactions";

const ERR_UNAUTHORIZED = 100;
const ERR_INVALID_NFT_ID = 101;
const ERR_INVALID_HASH = 102;
const ERR_INVALID_OWNER = 103;
const ERR_VERIFICATION_FAILED = 104;
const ERR_NO_METADATA = 105;
const ERR_NO_DETAILS = 106;
const ERR_ALREADY_VERIFIED = 107;
const ERR_INVALID_TIMESTAMP = 108;
const ERR_EXPIRED_CERT = 109;
const ERR_INVALID_ISSUER = 110;
const ERR_BATCH_LIMIT_EXCEEDED = 111;
const ERR_INVALID_PROVIDED_HASH = 112;
const ERR_INVALID_CLAIMED_OWNER = 113;
const ERR_VERIFIER_NOT_REGISTERED = 114;
const ERR_INVALID_VERIFIER = 115;
const ERR_VERIFICATION_LOG_NOT_FOUND = 116;
const ERR_INVALID_LOG_ID = 117;
const ERR_INVALID_BATCH_SIZE = 118;
const ERR_INVALID_EXPIRY = 119;
const ERR_INVALID_STATUS = 120;

interface VerificationLog {
  "nft-id": bigint;
  verifier: string;
  timestamp: bigint;
  valid: boolean;
  "provided-hash": Uint8Array;
  "claimed-owner": string | null;
}

interface Result<T, E> {
  ok: boolean;
  value: T | E;
}

type BatchResult = Array<{ valid: boolean; "nft-id": bigint }>;

class VerifierMock {
  state: {
    nextVerificationId: bigint;
    maxBatchSize: bigint;
    verificationFee: bigint;
    admin: string;
    verificationLogs: Map<bigint, VerificationLog>;
    batchVerifications: Map<bigint, Array<bigint>>;
    registeredVerifiers: Set<string>;
  } = {
    nextVerificationId: 0n,
    maxBatchSize: 10n,
    verificationFee: 100n,
    admin: "ST1ADMIN",
    verificationLogs: new Map(),
    batchVerifications: new Map(),
    registeredVerifiers: new Set(),
  };
  blockHeight: bigint = 0n;
  caller: string = "ST1CALLER";
  stxTransfers: Array<{ amount: bigint; from: string; to: string }> = [];
  nftMetadata: Map<bigint, { hash: Uint8Array; issuer: string; recipient: string }> = new Map();
  nftOwners: Map<bigint, string> = new Map();
  certDetails: Map<bigint, { "issue-date": bigint; "expiry-date": bigint | null }> = new Map();
  issuerRoles: Set<string> = new Set();

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextVerificationId: 0n,
      maxBatchSize: 10n,
      verificationFee: 100n,
      admin: "ST1ADMIN",
      verificationLogs: new Map(),
      batchVerifications: new Map(),
      registeredVerifiers: new Set(),
    };
    this.blockHeight = 0n;
    this.caller = "ST1CALLER";
    this.stxTransfers = [];
    this.nftMetadata = new Map();
    this.nftOwners = new Map();
    this.certDetails = new Map();
    this.issuerRoles = new Set();
  }

  mockGetMetadata(nftId: bigint): { hash: Uint8Array; issuer: string; recipient: string } | null {
    return this.nftMetadata.get(nftId) || null;
  }

  mockGetOwner(nftId: bigint): string | null {
    return this.nftOwners.get(nftId) || null;
  }

  mockGetCertificate(nftId: bigint): { "issue-date": bigint; "expiry-date": bigint | null } | null {
    return this.certDetails.get(nftId) || null;
  }

  mockCheckRole(principal: string, role: string): boolean {
    return role === "issuer" && this.issuerRoles.has(principal);
  }

  registerVerifier(): Result<boolean, number> {
    if (this.state.registeredVerifiers.has(this.caller)) {
      return { ok: false, value: ERR_ALREADY_VERIFIED };
    }
    this.state.registeredVerifiers.add(this.caller);
    return { ok: true, value: true };
  }

  unregisterVerifier(): Result<boolean, number> {
    if (!this.state.registeredVerifiers.has(this.caller)) {
      return { ok: false, value: ERR_VERIFIER_NOT_REGISTERED };
    }
    this.state.registeredVerifiers.delete(this.caller);
    return { ok: true, value: true };
  }

  setAdmin(newAdmin: string): Result<boolean, number> {
    if (this.caller !== this.state.admin) {
      return { ok: false, value: ERR_UNAUTHORIZED };
    }
    this.state.admin = newAdmin;
    return { ok: true, value: true };
  }

  setMaxBatchSize(newSize: bigint): Result<boolean, number> {
    if (this.caller !== this.state.admin) {
      return { ok: false, value: ERR_UNAUTHORIZED };
    }
    if (newSize <= 0n) {
      return { ok: false, value: ERR_INVALID_BATCH_SIZE };
    }
    this.state.maxBatchSize = newSize;
    return { ok: true, value: true };
  }

  setVerificationFee(newFee: bigint): Result<boolean, number> {
    if (this.caller !== this.state.admin) {
      return { ok: false, value: ERR_UNAUTHORIZED };
    }
    this.state.verificationFee = newFee;
    return { ok: true, value: true };
  }

  verifyCertificate(nftId: bigint, providedHash: Uint8Array): Result<{ valid: boolean; details: { "issue-date": bigint; "expiry-date": bigint | null }; "log-id": bigint }, number> {
    if (nftId <= 0n) return { ok: false, value: ERR_INVALID_NFT_ID };
    if (providedHash.length !== 32) return { ok: false, value: ERR_INVALID_HASH };
    if (!this.state.registeredVerifiers.has(this.caller)) return { ok: false, value: ERR_VERIFIER_NOT_REGISTERED };
    this.stxTransfers.push({ amount: this.state.verificationFee, from: this.caller, to: this.state.admin });
    const meta = this.mockGetMetadata(nftId);
    if (!meta) return { ok: false, value: ERR_NO_METADATA };
    if (!this.mockCheckRole(meta.issuer, "issuer")) return { ok: false, value: ERR_INVALID_ISSUER };
    if (!this.compareBuffers(meta.hash, providedHash)) return { ok: false, value: ERR_VERIFICATION_FAILED };
    const details = this.mockGetCertificate(nftId);
    if (!details) return { ok: false, value: ERR_NO_DETAILS };
    if (details["expiry-date"] !== null && details["expiry-date"] <= this.blockHeight) return { ok: false, value: ERR_EXPIRED_CERT };
    if (details["issue-date"] >= this.blockHeight) return { ok: false, value: ERR_INVALID_TIMESTAMP };
    const logId = this.state.nextVerificationId;
    this.state.verificationLogs.set(logId, {
      "nft-id": nftId,
      verifier: this.caller,
      timestamp: this.blockHeight,
      valid: true,
      "provided-hash": providedHash,
      "claimed-owner": null,
    });
    this.state.nextVerificationId += 1n;
    return { ok: true, value: { valid: true, details, "log-id": logId } };
  }

  verifyOwnership(nftId: bigint, claimedOwner: string): Result<{ valid: boolean; owner: string; "log-id": bigint }, number> {
    if (nftId <= 0n) return { ok: false, value: ERR_INVALID_NFT_ID };
    if (!this.state.registeredVerifiers.has(this.caller)) return { ok: false, value: ERR_VERIFIER_NOT_REGISTERED };
    this.stxTransfers.push({ amount: this.state.verificationFee, from: this.caller, to: this.state.admin });
    const owner = this.mockGetOwner(nftId);
    if (!owner) return { ok: false, value: ERR_INVALID_OWNER };
    if (owner !== claimedOwner) return { ok: false, value: ERR_INVALID_OWNER };
    const logId = this.state.nextVerificationId;
    this.state.verificationLogs.set(logId, {
      "nft-id": nftId,
      verifier: this.caller,
      timestamp: this.blockHeight,
      valid: true,
      "provided-hash": new Uint8Array(),
      "claimed-owner": claimedOwner,
    });
    this.state.nextVerificationId += 1n;
    return { ok: true, value: { valid: true, owner: claimedOwner, "log-id": logId } };
  }

  batchVerifyCertificates(nftIds: Array<bigint>, hashes: Array<Uint8Array>): Result<BatchResult, number> {
    const batchSize = BigInt(nftIds.length);
    if (batchSize <= 0n || batchSize > this.state.maxBatchSize) return { ok: false, value: ERR_INVALID_BATCH_SIZE };
    if (batchSize !== BigInt(hashes.length)) return { ok: false, value: ERR_INVALID_BATCH_SIZE };
    if (!this.state.registeredVerifiers.has(this.caller)) return { ok: false, value: ERR_VERIFIER_NOT_REGISTERED };
    this.stxTransfers.push({ amount: this.state.verificationFee * batchSize, from: this.caller, to: this.state.admin });
    const batchId = this.state.nextVerificationId;
    this.state.batchVerifications.set(batchId, nftIds);
    this.state.nextVerificationId += 1n;
    const results: BatchResult = [];
    for (let i = 0; i < nftIds.length; i++) {
      const res = this.verifyCertificate(nftIds[i], hashes[i]);
      if (res.ok) {
        results.push({ valid: res.value.valid, "nft-id": nftIds[i] });
      } else {
        return { ok: false, value: res.value };
      }
    }
    return { ok: true, value: results };
  }

  getVerificationLog(logId: bigint): VerificationLog | null {
    return this.state.verificationLogs.get(logId) || null;
  }

  getBatchVerification(batchId: bigint): Array<bigint> | null {
    return this.state.batchVerifications.get(batchId) || null;
  }

  isVerifierRegistered(verifier: string): Result<boolean, number> {
    return { ok: true, value: this.state.registeredVerifiers.has(verifier) };
  }

  getMaxBatchSize(): Result<bigint, number> {
    return { ok: true, value: this.state.maxBatchSize };
  }

  getVerificationFee(): Result<bigint, number> {
    return { ok: true, value: this.state.verificationFee };
  }

  getNextVerificationId(): Result<bigint, number> {
    return { ok: true, value: this.state.nextVerificationId };
  }

  checkCertificateValidity(nftId: bigint, providedHash: Uint8Array): Result<boolean, number> {
    const meta = this.mockGetMetadata(nftId);
    if (!meta) return { ok: false, value: ERR_NO_METADATA };
    return { ok: true, value: this.compareBuffers(meta.hash, providedHash) };
  }

  checkOwnership(nftId: bigint, claimedOwner: string): Result<boolean, number> {
    const owner = this.mockGetOwner(nftId);
    if (!owner) return { ok: false, value: ERR_INVALID_OWNER };
    return { ok: true, value: owner === claimedOwner };
  }

  private compareBuffers(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}

describe("VerifierContract", () => {
  let contract: VerifierMock;

  beforeEach(() => {
    contract = new VerifierMock();
    contract.reset();
  });

  it("registers a verifier successfully", () => {
    const result = contract.registerVerifier();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.registeredVerifiers.has("ST1CALLER")).toBe(true);
  });

  it("rejects duplicate verifier registration", () => {
    contract.registerVerifier();
    const result = contract.registerVerifier();
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ALREADY_VERIFIED);
  });

  it("unregisters a verifier successfully", () => {
    contract.registerVerifier();
    const result = contract.unregisterVerifier();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.registeredVerifiers.has("ST1CALLER")).toBe(false);
  });

  it("rejects unregistering non-registered verifier", () => {
    const result = contract.unregisterVerifier();
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_VERIFIER_NOT_REGISTERED);
  });

  it("sets admin successfully", () => {
    contract.caller = "ST1ADMIN";
    const result = contract.setAdmin("ST2NEWADMIN");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.admin).toBe("ST2NEWADMIN");
  });

  it("rejects set admin by non-admin", () => {
    const result = contract.setAdmin("ST2NEWADMIN");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_UNAUTHORIZED);
  });

  it("sets max batch size successfully", () => {
    contract.caller = "ST1ADMIN";
    const result = contract.setMaxBatchSize(20n);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.maxBatchSize).toBe(20n);
  });

  it("rejects invalid max batch size", () => {
    contract.caller = "ST1ADMIN";
    const result = contract.setMaxBatchSize(0n);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_BATCH_SIZE);
  });

  it("sets verification fee successfully", () => {
    contract.caller = "ST1ADMIN";
    const result = contract.setVerificationFee(200n);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.verificationFee).toBe(200n);
  });

  it("rejects verification with invalid nft id", () => {
    contract.registerVerifier();
    const result = contract.verifyCertificate(0n, new Uint8Array(32));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_NFT_ID);
  });

  it("rejects verification with invalid hash", () => {
    contract.registerVerifier();
    const result = contract.verifyCertificate(1n, new Uint8Array(31));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_HASH);
  });

  it("rejects verification by non-registered verifier", () => {
    const result = contract.verifyCertificate(1n, new Uint8Array(32));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_VERIFIER_NOT_REGISTERED);
  });

  it("rejects verification with no metadata", () => {
    contract.registerVerifier();
    const result = contract.verifyCertificate(1n, new Uint8Array(32));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NO_METADATA);
  });

  it("rejects verification with invalid issuer", () => {
    contract.registerVerifier();
    const nftId = 1n;
    const hash = new Uint8Array(32).fill(1);
    contract.nftMetadata.set(nftId, { hash, issuer: "ST1ISSUER", recipient: "ST1RECIP" });
    contract.certDetails.set(nftId, { "issue-date": 1n, "expiry-date": null });
    const result = contract.verifyCertificate(nftId, hash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_ISSUER);
  });

  it("rejects verification with hash mismatch", () => {
    contract.registerVerifier();
    const nftId = 1n;
    const storedHash = new Uint8Array(32).fill(1);
    const providedHash = new Uint8Array(32).fill(2);
    contract.nftMetadata.set(nftId, { hash: storedHash, issuer: "ST1ISSUER", recipient: "ST1RECIP" });
    contract.certDetails.set(nftId, { "issue-date": 1n, "expiry-date": null });
    contract.issuerRoles.add("ST1ISSUER");
    const result = contract.verifyCertificate(nftId, providedHash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_VERIFICATION_FAILED);
  });

  it("rejects verification with no details", () => {
    contract.registerVerifier();
    const nftId = 1n;
    const hash = new Uint8Array(32).fill(1);
    contract.nftMetadata.set(nftId, { hash, issuer: "ST1ISSUER", recipient: "ST1RECIP" });
    contract.issuerRoles.add("ST1ISSUER");
    const result = contract.verifyCertificate(nftId, hash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NO_DETAILS);
  });

  it("rejects expired certificate", () => {
    contract.registerVerifier();
    const nftId = 1n;
    const hash = new Uint8Array(32).fill(1);
    contract.nftMetadata.set(nftId, { hash, issuer: "ST1ISSUER", recipient: "ST1RECIP" });
    contract.certDetails.set(nftId, { "issue-date": 1n, "expiry-date": 10n });
    contract.issuerRoles.add("ST1ISSUER");
    contract.blockHeight = 11n;
    const result = contract.verifyCertificate(nftId, hash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_EXPIRED_CERT);
  });

  it("rejects invalid issue date", () => {
    contract.registerVerifier();
    const nftId = 1n;
    const hash = new Uint8Array(32).fill(1);
    contract.nftMetadata.set(nftId, { hash, issuer: "ST1ISSUER", recipient: "ST1RECIP" });
    contract.certDetails.set(nftId, { "issue-date": 100n, "expiry-date": null });
    contract.issuerRoles.add("ST1ISSUER");
    contract.blockHeight = 50n;
    const result = contract.verifyCertificate(nftId, hash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_TIMESTAMP);
  });

  it("verifies ownership successfully", () => {
    contract.registerVerifier();
    const nftId = 1n;
    const claimedOwner = "ST1OWNER";
    contract.nftOwners.set(nftId, claimedOwner);
    const result = contract.verifyOwnership(nftId, claimedOwner);
    expect(result.ok).toBe(true);
    expect(result.value.valid).toBe(true);
    expect(result.value.owner).toBe(claimedOwner);
    expect(result.value["log-id"]).toBe(0n);
    expect(contract.stxTransfers).toEqual([{ amount: 100n, from: "ST1CALLER", to: "ST1ADMIN" }]);
  });

  it("rejects ownership verification with invalid nft id", () => {
    contract.registerVerifier();
    const result = contract.verifyOwnership(0n, "ST1OWNER");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_NFT_ID);
  });

  it("rejects ownership verification by non-registered verifier", () => {
    const result = contract.verifyOwnership(1n, "ST1OWNER");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_VERIFIER_NOT_REGISTERED);
  });

  it("rejects ownership verification with no owner", () => {
    contract.registerVerifier();
    const result = contract.verifyOwnership(1n, "ST1OWNER");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_OWNER);
  });

  it("rejects ownership verification with mismatch", () => {
    contract.registerVerifier();
    contract.nftOwners.set(1n, "ST2OTHER");
    const result = contract.verifyOwnership(1n, "ST1OWNER");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_OWNER);
  });

  it("rejects batch verification with invalid size", () => {
    contract.registerVerifier();
    const result = contract.batchVerifyCertificates([], []);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_BATCH_SIZE);
  });

  it("rejects batch verification with mismatched lengths", () => {
    contract.registerVerifier();
    const result = contract.batchVerifyCertificates([1n], []);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_BATCH_SIZE);
  });

  it("rejects batch verification exceeding max size", () => {
    contract.registerVerifier();
    const nftIds = Array.from({ length: 11 }, (_, i) => BigInt(i + 1));
    const hashes = Array.from({ length: 11 }, () => new Uint8Array(32));
    const result = contract.batchVerifyCertificates(nftIds, hashes);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_BATCH_SIZE);
  });

  it("gets batch verification successfully", () => {
    contract.registerVerifier();
    const nftIds = [1n, 2n];
    const hashes = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
    contract.nftMetadata.set(1n, { hash: hashes[0], issuer: "ST1ISSUER", recipient: "ST1RECIP" });
    contract.nftMetadata.set(2n, { hash: hashes[1], issuer: "ST1ISSUER", recipient: "ST1RECIP" });
    contract.certDetails.set(1n, { "issue-date": 1n, "expiry-date": null });
    contract.certDetails.set(2n, { "issue-date": 1n, "expiry-date": null });
    contract.issuerRoles.add("ST1ISSUER");
    contract.batchVerifyCertificates(nftIds, hashes);
    const batch = contract.getBatchVerification(2n);
    expect(batch).toEqual(null);
  });

  it("checks if verifier is registered", () => {
    contract.registerVerifier();
    const result = contract.isVerifierRegistered("ST1CALLER");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });

  it("gets max batch size", () => {
    const result = contract.getMaxBatchSize();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(10n);
  });

  it("gets verification fee", () => {
    const result = contract.getVerificationFee();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(100n);
  });

  it("gets next verification id", () => {
    const result = contract.getNextVerificationId();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0n);
  });

  it("checks certificate validity successfully", () => {
    const nftId = 1n;
    const hash = new Uint8Array(32).fill(1);
    contract.nftMetadata.set(nftId, { hash, issuer: "ST1ISSUER", recipient: "ST1RECIP" });
    const result = contract.checkCertificateValidity(nftId, hash);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });

  it("rejects check certificate validity with no metadata", () => {
    const result = contract.checkCertificateValidity(1n, new Uint8Array(32));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NO_METADATA);
  });

  it("checks ownership successfully", () => {
    const nftId = 1n;
    const owner = "ST1OWNER";
    contract.nftOwners.set(nftId, owner);
    const result = contract.checkOwnership(nftId, owner);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });

  it("rejects check ownership with no owner", () => {
    const result = contract.checkOwnership(1n, "ST1OWNER");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_OWNER);
  });
});