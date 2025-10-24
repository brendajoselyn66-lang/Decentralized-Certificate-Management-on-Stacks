import { describe, it, expect, beforeEach } from "vitest";
import { Cl } from "@stacks/transactions";

interface Metadata {
  issuer: string;
  recipient: string;
  hash: Uint8Array;
  issueDate: number;
  expiryDate: number | null;
  status: string;
}

interface Attribute {
  key: string;
  value: string;
}

interface IssuerLimit {
  mintLimit: number;
  mintedCount: number;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class CertificateNFTMock {
  state: {
    nextId: number;
    mintFrozen: boolean;
    admin: string;
    issuerRegistry: string;
    nftOwners: Map<number, string>;
    nftMetadata: Map<number, Metadata>;
    nftAttributes: Map<number, Attribute[]>;
    issuerLimits: Map<string, IssuerLimit>;
  } = {
    nextId: 1,
    mintFrozen: false,
    admin: "ST1ADMIN",
    issuerRegistry: "SP000000000000000000002Q6VF78",
    nftOwners: new Map(),
    nftMetadata: new Map(),
    nftAttributes: new Map(),
    issuerLimits: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1ISSUER";
  events: Array<{ event: string; [key: string]: any }> = [];

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextId: 1,
      mintFrozen: false,
      admin: "ST1ADMIN",
      issuerRegistry: "SP000000000000000000002Q6VF78",
      nftOwners: new Map(),
      nftMetadata: new Map(),
      nftAttributes: new Map(),
      issuerLimits: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1ISSUER";
    this.events = [];
  }

  checkIssuer(principal: string): Result<boolean> {
    return { ok: true, value: principal === "ST1ISSUER" };
  }

  getIssuerInfo(principal: string): Result<{ name: string; verified: boolean } | null> {
    return principal === "ST1ISSUER" ? { ok: true, value: { name: "TestIssuer", verified: true } } : { ok: true, value: null };
  }

  getLastTokenId(): Result<number> {
    return { ok: true, value: this.state.nextId - 1 };
  }

  getTokenUri(id: number): Result<null> {
    return { ok: true, value: null };
  }

  getOwner(id: number): Result<string | null> {
    return { ok: true, value: this.state.nftOwners.get(id) || null };
  }

  getMetadata(id: number): Metadata | null {
    return this.state.nftMetadata.get(id) || null;
  }

  getAttributes(id: number): Attribute[] | null {
    return this.state.nftAttributes.get(id) || null;
  }

  getIssuerLimit(issuer: string): IssuerLimit | null {
    return this.state.issuerLimits.get(issuer) || null;
  }

  isMintFrozen(): Result<boolean> {
    return { ok: true, value: this.state.mintFrozen };
  }

  setIssuerRegistry(registry: string): Result<boolean> {
    if (this.caller !== this.state.admin) return { ok: false, value: 100 };
    this.state.issuerRegistry = registry;
    return { ok: true, value: true };
  }

  setMintLimit(issuer: string, limit: number): Result<boolean> {
    if (this.caller !== this.state.admin) return { ok: false, value: 100 };
    if (!this.getIssuerInfo(issuer).value) return { ok: false, value: 100 };
    this.state.issuerLimits.set(issuer, { mintLimit: limit, mintedCount: this.state.issuerLimits.get(issuer)?.mintedCount || 0 });
    return { ok: true, value: true };
  }

  freezeMint(): Result<boolean> {
    if (this.caller !== this.state.admin) return { ok: false, value: 100 };
    if (this.state.mintFrozen) return { ok: false, value: 106 };
    this.state.mintFrozen = true;
    return { ok: true, value: true };
  }

  unfreezeMint(): Result<boolean> {
    if (this.caller !== this.state.admin) return { ok: false, value: 100 };
    if (!this.state.mintFrozen) return { ok: false, value: 107 };
    this.state.mintFrozen = false;
    return { ok: true, value: true };
  }

  mint(recipient: string, hash: Uint8Array, issueDate: number, expiry: number | null, attributes: Attribute[]): Result<number> {
    if (this.state.mintFrozen) return { ok: false, value: 105 };
    if (!this.getIssuerInfo(this.caller).value) return { ok: false, value: 100 };
    if (!this.checkIssuer(this.caller).value) return { ok: false, value: 100 };
    if (recipient === "SP000000000000000000002Q6VF78") return { ok: false, value: 102 };
    if (hash.length === 0) return { ok: false, value: 103 };
    const limits = this.state.issuerLimits.get(this.caller) || { mintLimit: 100, mintedCount: 0 };
    if (limits.mintedCount >= limits.mintLimit && limits.mintLimit !== 0) return { ok: false, value: 100 };
    const id = this.state.nextId;
    this.state.nftOwners.set(id, recipient);
    this.state.nftMetadata.set(id, { issuer: this.caller, recipient, hash, issueDate, expiryDate: expiry, status: "active" });
    this.state.nftAttributes.set(id, attributes);
    this.state.issuerLimits.set(this.caller, { mintLimit: limits.mintLimit, mintedCount: limits.mintedCount + 1 });
    this.state.nextId++;
    this.events.push({ event: "nft-minted", id, recipient });
    return { ok: true, value: id };
  }

  transfer(id: number, sender: string, recipient: string): Result<boolean> {
    if (this.caller !== sender) return { ok: false, value: 101 };
    if (!this.state.nftOwners.has(id)) return { ok: false, value: 104 };
    if (this.state.nftOwners.get(id) !== sender) return { ok: false, value: 101 };
    if (recipient === "SP000000000000000000002Q6VF78") return { ok: false, value: 102 };
    this.state.nftOwners.set(id, recipient);
    const metadata = this.state.nftMetadata.get(id)!;
    this.state.nftMetadata.set(id, { ...metadata, recipient });
    this.events.push({ event: "nft-transferred", id, from: sender, to: recipient });
    return { ok: true, value: true };
  }

  updateStatus(id: number, status: string): Result<boolean> {
    const metadata = this.state.nftMetadata.get(id);
    if (!metadata) return { ok: false, value: 104 };
    if (metadata.issuer !== this.caller) return { ok: false, value: 100 };
    if (!["active", "revoked", "expired"].includes(status)) return { ok: false, value: 109 };
    this.state.nftMetadata.set(id, { ...metadata, status });
    this.events.push({ event: "status-updated", id, status });
    return { ok: true, value: true };
  }

  addAttribute(id: number, key: string, value: string): Result<boolean> {
    const metadata = this.state.nftMetadata.get(id);
    if (!metadata) return { ok: false, value: 104 };
    if (metadata.issuer !== this.caller) return { ok: false, value: 100 };
    if (key.length === 0) return { ok: false, value: 108 };
    const attributes = this.state.nftAttributes.get(id) || [];
    if (attributes.length >= 10) return { ok: false, value: 108 };
    this.state.nftAttributes.set(id, [...attributes, { key, value }]);
    this.events.push({ event: "attribute-added", id, key, value });
    return { ok: true, value: true };
  }

  burn(id: number): Result<boolean> {
    const metadata = this.state.nftMetadata.get(id);
    if (!metadata) return { ok: false, value: 104 };
    if (this.caller !== this.state.admin && metadata.issuer !== this.caller) return { ok: false, value: 100 };
    this.state.nftOwners.delete(id);
    this.state.nftMetadata.delete(id);
    this.state.nftAttributes.delete(id);
    this.events.push({ event: "nft-burned", id });
    return { ok: true, value: true };
  }
}

describe("CertificateNFT", () => {
  let contract: CertificateNFTMock;

  beforeEach(() => {
    contract = new CertificateNFTMock();
    contract.reset();
  });

  it("mints an NFT successfully", () => {
    const hash = new Uint8Array(32).fill(1);
    contract.caller = "ST1ISSUER";
    const result = contract.mint("ST1RECIPIENT", hash, 100, null, [{ key: "type", value: "Degree" }]);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(1);
    const metadata = contract.getMetadata(1);
    expect(metadata).toEqual({
      issuer: "ST1ISSUER",
      recipient: "ST1RECIPIENT",
      hash,
      issueDate: 100,
      expiryDate: null,
      status: "active",
    });
    const attributes = contract.getAttributes(1);
    expect(attributes).toEqual([{ key: "type", value: "Degree" }]);
    expect(contract.getOwner(1)).toEqual({ ok: true, value: "ST1RECIPIENT" });
    expect(contract.getIssuerLimit("ST1ISSUER")).toEqual({ mintLimit: 100, mintedCount: 1 });
    expect(contract.events).toContainEqual({ event: "nft-minted", id: 1, recipient: "ST1RECIPIENT" });
  });

  it("rejects minting when frozen", () => {
    contract.caller = "ST1ADMIN";
    contract.freezeMint();
    contract.caller = "ST1ISSUER";
    const hash = new Uint8Array(32).fill(1);
    const result = contract.mint("ST1RECIPIENT", hash, 100, null, []);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(105);
  });

  it("rejects minting by non-issuer", () => {
    contract.caller = "ST2FAKE";
    const hash = new Uint8Array(32).fill(1);
    const result = contract.mint("ST1RECIPIENT", hash, 100, null, []);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(100);
  });

  it("rejects minting with invalid recipient", () => {
    contract.caller = "ST1ISSUER";
    const hash = new Uint8Array(32).fill(1);
    const result = contract.mint("SP000000000000000000002Q6VF78", hash, 100, null, []);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(102);
  });

  it("rejects minting with empty hash", () => {
    contract.caller = "ST1ISSUER";
    const result = contract.mint("ST1RECIPIENT", new Uint8Array(0), 100, null, []);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(103);
  });

  it("transfers an NFT successfully", () => {
    const hash = new Uint8Array(32).fill(1);
    contract.caller = "ST1ISSUER";
    contract.mint("ST1RECIPIENT", hash, 100, null, []);
    contract.caller = "ST1RECIPIENT";
    const result = contract.transfer(1, "ST1RECIPIENT", "ST2RECIPIENT");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.getOwner(1)).toEqual({ ok: true, value: "ST2RECIPIENT" });
    expect(contract.getMetadata(1)?.recipient).toBe("ST2RECIPIENT");
    expect(contract.events).toContainEqual({ event: "nft-transferred", id: 1, from: "ST1RECIPIENT", to: "ST2RECIPIENT" });
  });

  it("rejects transfer by non-owner", () => {
    const hash = new Uint8Array(32).fill(1);
    contract.caller = "ST1ISSUER";
    contract.mint("ST1RECIPIENT", hash, 100, null, []);
    contract.caller = "ST2FAKE";
    const result = contract.transfer(1, "ST1RECIPIENT", "ST2RECIPIENT");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(101);
  });

  it("rejects transfer of non-existent NFT", () => {
    contract.caller = "ST1RECIPIENT";
    const result = contract.transfer(99, "ST1RECIPIENT", "ST2RECIPIENT");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(104);
  });

  it("updates status successfully", () => {
    const hash = new Uint8Array(32).fill(1);
    contract.caller = "ST1ISSUER";
    contract.mint("ST1RECIPIENT", hash, 100, null, []);
    contract.caller = "ST1ISSUER";
    const result = contract.updateStatus(1, "revoked");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.getMetadata(1)?.status).toBe("revoked");
    expect(contract.events).toContainEqual({ event: "status-updated", id: 1, status: "revoked" });
  });

  it("rejects status update by non-issuer", () => {
    const hash = new Uint8Array(32).fill(1);
    contract.caller = "ST1ISSUER";
    contract.mint("ST1RECIPIENT", hash, 100, null, []);
    contract.caller = "ST2FAKE";
    const result = contract.updateStatus(1, "revoked");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(100);
  });

  it("rejects invalid status", () => {
    const hash = new Uint8Array(32).fill(1);
    contract.caller = "ST1ISSUER";
    contract.mint("ST1RECIPIENT", hash, 100, null, []);
    contract.caller = "ST1ISSUER";
    const result = contract.updateStatus(1, "invalid");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(109);
  });

  it("adds attribute successfully", () => {
    const hash = new Uint8Array(32).fill(1);
    contract.caller = "ST1ISSUER";
    contract.mint("ST1RECIPIENT", hash, 100, null, []);
    contract.caller = "ST1ISSUER";
    const result = contract.addAttribute(1, "course", "Mathematics");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.getAttributes(1)).toContainEqual({ key: "course", value: "Mathematics" });
    expect(contract.events).toContainEqual({ event: "attribute-added", id: 1, key: "course", value: "Mathematics" });
  });

  it("rejects adding attribute by non-issuer", () => {
    const hash = new Uint8Array(32).fill(1);
    contract.caller = "ST1ISSUER";
    contract.mint("ST1RECIPIENT", hash, 100, null, []);
    contract.caller = "ST2FAKE";
    const result = contract.addAttribute(1, "course", "Mathematics");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(100);
  });

  it("rejects adding attribute to non-existent NFT", () => {
    contract.caller = "ST1ISSUER";
    const result = contract.addAttribute(99, "course", "Mathematics");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(104);
  });

  it("burns NFT successfully", () => {
    const hash = new Uint8Array(32).fill(1);
    contract.caller = "ST1ISSUER";
    contract.mint("ST1RECIPIENT", hash, 100, null, []);
    contract.caller = "ST1ISSUER";
    const result = contract.burn(1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.getOwner(1)).toEqual({ ok: true, value: null });
    expect(contract.getMetadata(1)).toBe(null);
    expect(contract.getAttributes(1)).toBe(null);
    expect(contract.events).toContainEqual({ event: "nft-burned", id: 1 });
  });

  it("rejects burn by non-issuer or non-admin", () => {
    const hash = new Uint8Array(32).fill(1);
    contract.caller = "ST1ISSUER";
    contract.mint("ST1RECIPIENT", hash, 100, null, []);
    contract.caller = "ST2FAKE";
    const result = contract.burn(1);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(100);
  });

  it("sets mint limit successfully", () => {
    contract.caller = "ST1ADMIN";
    const result = contract.setMintLimit("ST1ISSUER", 10);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.getIssuerLimit("ST1ISSUER")).toEqual({ mintLimit: 10, mintedCount: 0 });
  });

  it("rejects mint limit by non-admin", () => {
    contract.caller = "ST1ISSUER";
    const result = contract.setMintLimit("ST1ISSUER", 10);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(100);
  });

  it("sets issuer registry successfully", () => {
    contract.caller = "ST1ADMIN";
    const result = contract.setIssuerRegistry("ST2REGISTRY");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.issuerRegistry).toBe("ST2REGISTRY");
  });

  it("rejects issuer registry by non-admin", () => {
    contract.caller = "ST1ISSUER";
    const result = contract.setIssuerRegistry("ST2REGISTRY");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(100);
  });
});