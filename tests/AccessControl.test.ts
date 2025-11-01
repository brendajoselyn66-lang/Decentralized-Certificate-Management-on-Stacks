import { describe, it, expect, beforeEach } from "vitest";
import { stringAsciiCV, stringUtf8CV, uintCV, optionalCV, noneCV, someCV, boolCV, listCV, principalCV } from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_ALREADY_ASSIGNED = 101;
const ERR_ROLE_NOT_FOUND = 102;
const ERR_INVALID_ROLE_NAME = 103;
const ERR_NOT_ROLE_ADMIN = 104;
const ERR_INVALID_TIMESTAMP = 105;
const ERR_AUTHORITY_NOT_VERIFIED = 106;
const ERR_INVALID_FEE = 107;
const ERR_MAX_ROLES_EXCEEDED = 108;
const ERR_INVALID_DESCRIPTION = 109;
const ERR_INVALID_EXPIRY = 110;
const ERR_ROLE_ALREADY_EXISTS = 111;
const ERR_INVALID_UPDATE_PARAM = 112;
const ERR_MEMBER_NOT_FOUND = 113;
const ERR_ROLE_UPDATE_NOT_ALLOWED = 114;
const ERR_INVALID_PRINCIPAL = 115;
const ERR_EXPIRY_PASSED = 116;
const ERR_INVALID_MAX_MEMBERS = 117;
const ERR_MAX_MEMBERS_EXCEEDED = 118;
const ERR_INVALID_STATUS = 119;
const ERR_AUTHORITY_ALREADY_SET = 120;

interface Role {
  name: string;
  description: string;
  admin: string;
  timestamp: number;
  expiry: number | null;
  status: boolean;
}

interface RoleUpdate {
  updateName: string;
  updateDescription: string;
  updateTimestamp: number;
  updater: string;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class AccessControlMock {
  state: {
    contractOwner: string;
    nextRoleId: number;
    maxRoles: number;
    grantFee: number;
    authorityContract: string | null;
    maxMembersPerRole: number;
    roles: Map<number, Role>;
    rolesByName: Map<string, number>;
    roleMembers: Map<number, string[]>;
    memberRoles: Map<string, number[]>;
    roleUpdates: Map<number, RoleUpdate>;
  } = {
    contractOwner: "ST1TEST",
    nextRoleId: 0,
    maxRoles: 1000,
    grantFee: 1000,
    authorityContract: null,
    maxMembersPerRole: 1000,
    roles: new Map(),
    rolesByName: new Map(),
    roleMembers: new Map(),
    memberRoles: new Map(),
    roleUpdates: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1TEST";
  stxTransfers: Array<{ amount: number; from: string; to: string | null }> = [];

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      contractOwner: "ST1TEST",
      nextRoleId: 0,
      maxRoles: 1000,
      grantFee: 1000,
      authorityContract: null,
      maxMembersPerRole: 1000,
      roles: new Map(),
      rolesByName: new Map(),
      roleMembers: new Map(),
      memberRoles: new Map(),
      roleUpdates: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1TEST";
    this.stxTransfers = [];
  }

  isAdmin(account: string): boolean {
    if (account === this.state.contractOwner) return true;
    const roles = this.state.memberRoles.get(account) || [];
    return roles.some(id => {
      const role = this.state.roles.get(id);
      return role ? role.admin === account && this.isRoleActive(id) : false;
    });
  }

  isRoleAdmin(account: string, roleId: number): boolean {
    const role = this.state.roles.get(roleId);
    return role ? role.admin === account && this.isRoleActive(roleId) : false;
  }

  isRoleActive(id: number): boolean {
    const role = this.state.roles.get(id);
    if (!role) return false;
    if (role.expiry !== null) {
      return role.expiry >= this.blockHeight;
    }
    return true;
  }

  setAuthorityContract(contractPrincipal: string): Result<boolean> {
    if (contractPrincipal === "SP000000000000000000002Q6VF78") {
      return { ok: false, value: ERR_INVALID_PRINCIPAL };
    }
    if (this.state.authorityContract !== null) {
      return { ok: false, value: ERR_AUTHORITY_ALREADY_SET };
    }
    this.state.authorityContract = contractPrincipal;
    return { ok: true, value: true };
  }

  setGrantFee(newFee: number): Result<boolean> {
    if (!this.isAdmin(this.caller)) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (newFee < 0) return { ok: false, value: ERR_INVALID_FEE };
    this.state.grantFee = newFee;
    return { ok: true, value: true };
  }

  setMaxRoles(newMax: number): Result<boolean> {
    if (!this.isAdmin(this.caller)) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (newMax <= 0) return { ok: false, value: ERR_INVALID_UPDATE_PARAM };
    this.state.maxRoles = newMax;
    return { ok: true, value: true };
  }

  setMaxMembersPerRole(newMax: number): Result<boolean> {
    if (!this.isAdmin(this.caller)) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (newMax <= 0 || newMax > 1000) return { ok: false, value: ERR_INVALID_MAX_MEMBERS };
    this.state.maxMembersPerRole = newMax;
    return { ok: true, value: true };
  }

  createRole(
    name: string,
    description: string,
    expiry: number | null
  ): Result<number> {
    if (!this.isAdmin(this.caller)) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (this.state.nextRoleId >= this.state.maxRoles) return { ok: false, value: ERR_MAX_ROLES_EXCEEDED };
    if (name.length === 0 || name.length > 32) return { ok: false, value: ERR_INVALID_ROLE_NAME };
    if (description.length > 256) return { ok: false, value: ERR_INVALID_DESCRIPTION };
    if (expiry !== null && expiry <= this.blockHeight) return { ok: false, value: ERR_INVALID_EXPIRY };
    if (this.state.rolesByName.has(name)) return { ok: false, value: ERR_ROLE_ALREADY_EXISTS };

    const id = this.state.nextRoleId;
    this.state.roles.set(id, {
      name,
      description,
      admin: this.caller,
      timestamp: this.blockHeight,
      expiry,
      status: true,
    });
    this.state.rolesByName.set(name, id);
    this.state.nextRoleId++;
    return { ok: true, value: id };
  }

  grantRole(roleId: number, member: string): Result<boolean> {
    const role = this.state.roles.get(roleId);
    if (!role) return { ok: false, value: ERR_ROLE_NOT_FOUND };
    if (!this.isRoleAdmin(this.caller, roleId)) return { ok: false, value: ERR_NOT_ROLE_ADMIN };
    if (!this.isRoleActive(roleId)) return { ok: false, value: ERR_EXPIRY_PASSED };
    const memberRoles = this.state.memberRoles.get(member) || [];
    if (memberRoles.includes(roleId)) return { ok: false, value: ERR_ALREADY_ASSIGNED };
    const roleMembers = this.state.roleMembers.get(roleId) || [];
    if (roleMembers.length >= this.state.maxMembersPerRole) return { ok: false, value: ERR_MAX_MEMBERS_EXCEEDED };

    roleMembers.push(member);
    this.state.roleMembers.set(roleId, roleMembers);
    memberRoles.push(roleId);
    this.state.memberRoles.set(member, memberRoles);

    if (this.state.grantFee > 0 && this.state.authorityContract) {
      this.stxTransfers.push({ amount: this.state.grantFee, from: this.caller, to: this.state.authorityContract });
    }

    return { ok: true, value: true };
  }

  revokeRole(roleId: number, member: string): Result<boolean> {
    const role = this.state.roles.get(roleId);
    if (!role) return { ok: false, value: ERR_ROLE_NOT_FOUND };
    if (!this.isRoleAdmin(this.caller, roleId)) return { ok: false, value: ERR_NOT_ROLE_ADMIN };
    const memberRoles = this.state.memberRoles.get(member) || [];
    if (!memberRoles.includes(roleId)) return { ok: false, value: ERR_MEMBER_NOT_FOUND };

    const newMemberRoles = memberRoles.filter(id => id !== roleId);
    this.state.memberRoles.set(member, newMemberRoles);
    const roleMembers = this.state.roleMembers.get(roleId) || [];
    const newRoleMembers = roleMembers.filter(p => p !== member);
    this.state.roleMembers.set(roleId, newRoleMembers);

    return { ok: true, value: true };
  }

  updateRole(roleId: number, updateName: string, updateDescription: string): Result<boolean> {
    const role = this.state.roles.get(roleId);
    if (!role) return { ok: false, value: ERR_ROLE_NOT_FOUND };
    if (!this.isRoleAdmin(this.caller, roleId)) return { ok: false, value: ERR_NOT_ROLE_ADMIN };
    if (updateName.length === 0 || updateName.length > 32) return { ok: false, value: ERR_INVALID_ROLE_NAME };
    if (updateDescription.length > 256) return { ok: false, value: ERR_INVALID_DESCRIPTION };
    if (updateName !== role.name && this.state.rolesByName.has(updateName)) {
      return { ok: false, value: ERR_ROLE_ALREADY_EXISTS };
    }

    if (updateName !== role.name) {
      this.state.rolesByName.delete(role.name);
      this.state.rolesByName.set(updateName, roleId);
    }

    const updated: Role = {
      ...role,
      name: updateName,
      description: updateDescription,
      timestamp: this.blockHeight,
    };
    this.state.roles.set(roleId, updated);
    this.state.roleUpdates.set(roleId, {
      updateName,
      updateDescription,
      updateTimestamp: this.blockHeight,
      updater: this.caller,
    });
    return { ok: true, value: true };
  }

  deactivateRole(roleId: number): Result<boolean> {
    const role = this.state.roles.get(roleId);
    if (!role) return { ok: false, value: ERR_ROLE_NOT_FOUND };
    if (!this.isAdmin(this.caller)) return { ok: false, value: ERR_NOT_AUTHORIZED };

    this.state.roles.set(roleId, { ...role, status: false });
    return { ok: true, value: true };
  }

  getRoleCount(): Result<number> {
    return { ok: true, value: this.state.nextRoleId };
  }

  hasRole(member: string, roleId: number): boolean {
    const roles = this.state.memberRoles.get(member) || [];
    return roles.includes(roleId);
  }

  isRoleRegistered(name: string): boolean {
    return this.state.rolesByName.has(name);
  }
}

describe("AccessControl", () => {
  let contract: AccessControlMock;

  beforeEach(() => {
    contract = new AccessControlMock();
    contract.reset();
  });

  it("creates a role successfully", () => {
    contract.createRole("admin", "Admin role", null);
    contract.caller = "ST2TEST";
    const result = contract.createRole("issuer", "Issuer role", 100);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
    contract.caller = "ST1TEST";
    const result2 = contract.createRole("issuer", "Issuer role", 100);
    expect(result2.ok).toBe(true);
    expect(result2.value).toBe(1);
    const role = contract.state.roles.get(1);
    expect(role?.name).toBe("issuer");
    expect(role?.description).toBe("Issuer role");
    expect(role?.admin).toBe("ST1TEST");
    expect(role?.expiry).toBe(100);
  });

  it("rejects duplicate role names", () => {
    contract.createRole("admin", "Admin role", null);
    const result = contract.createRole("admin", "Duplicate", null);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ROLE_ALREADY_EXISTS);
  });

  it("rejects invalid role name", () => {
    const result = contract.createRole("", "Invalid", null);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_ROLE_NAME);
  });

  it("grants role successfully", () => {
    contract.createRole("issuer", "Issuer", null);
    contract.setAuthorityContract("STAUTH");
    const result = contract.grantRole(0, "ST2TEST");
    expect(result.ok).toBe(true);
    expect(contract.hasRole("ST2TEST", 0)).toBe(true);
    expect(contract.stxTransfers).toEqual([{ amount: 1000, from: "ST1TEST", to: "STAUTH" }]);
  });

  it("rejects grant if not role admin", () => {
    contract.createRole("issuer", "Issuer", null);
    contract.caller = "ST3FAKE";
    const result = contract.grantRole(0, "ST2TEST");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_ROLE_ADMIN);
  });

  it("rejects grant if already assigned", () => {
    contract.createRole("issuer", "Issuer", null);
    contract.grantRole(0, "ST2TEST");
    const result = contract.grantRole(0, "ST2TEST");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ALREADY_ASSIGNED);
  });

  it("rejects grant if max members exceeded", () => {
    contract.createRole("issuer", "Issuer", null);
    contract.state.maxMembersPerRole = 1;
    contract.grantRole(0, "ST2TEST");
    const result = contract.grantRole(0, "ST3TEST");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_MEMBERS_EXCEEDED);
  });

  it("revokes role successfully", () => {
    contract.createRole("issuer", "Issuer", null);
    contract.grantRole(0, "ST2TEST");
    const result = contract.revokeRole(0, "ST2TEST");
    expect(result.ok).toBe(true);
    expect(contract.hasRole("ST2TEST", 0)).toBe(false);
  });

  it("rejects revoke if not member", () => {
    contract.createRole("issuer", "Issuer", null);
    const result = contract.revokeRole(0, "ST2TEST");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MEMBER_NOT_FOUND);
  });

  it("updates role successfully", () => {
    contract.createRole("issuer", "Old desc", null);
    const result = contract.updateRole(0, "newissuer", "New desc");
    expect(result.ok).toBe(true);
    const role = contract.state.roles.get(0);
    expect(role?.name).toBe("newissuer");
    expect(role?.description).toBe("New desc");
  });

  it("rejects update with duplicate name", () => {
    contract.createRole("issuer", "Desc1", null);
    contract.createRole("verifier", "Desc2", null);
    const result = contract.updateRole(0, "verifier", "New desc");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ROLE_ALREADY_EXISTS);
  });

  it("deactivates role successfully", () => {
    contract.createRole("issuer", "Desc", null);
    const result = contract.deactivateRole(0);
    expect(result.ok).toBe(true);
    const role = contract.state.roles.get(0);
    expect(role?.status).toBe(false);
  });

  it("sets grant fee successfully", () => {
    contract.createRole("admin", "Admin", null);
    const result = contract.setGrantFee(2000);
    expect(result.ok).toBe(true);
    expect(contract.state.grantFee).toBe(2000);
  });

  it("returns correct role count", () => {
    contract.createRole("admin", "Admin", null);
    contract.createRole("issuer", "Issuer", null);
    const result = contract.getRoleCount();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });

  it("checks role existence correctly", () => {
    contract.createRole("issuer", "Issuer", null);
    expect(contract.isRoleRegistered("issuer")).toBe(true);
    expect(contract.isRoleRegistered("nonexistent")).toBe(false);
  });

  it("rejects creation with expiry passed", () => {
    const result = contract.createRole("issuer", "Issuer", 0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_EXPIRY);
  });

  it("rejects max roles exceeded", () => {
    contract.state.maxRoles = 1;
    contract.createRole("admin", "Admin", null);
    const result = contract.createRole("issuer", "Issuer", null);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_ROLES_EXCEEDED);
  });

  it("sets authority contract successfully", () => {
    const result = contract.setAuthorityContract("STAUTH");
    expect(result.ok).toBe(true);
    expect(contract.state.authorityContract).toBe("STAUTH");
  });

  it("rejects invalid authority principal", () => {
    const result = contract.setAuthorityContract("SP000000000000000000002Q6VF78");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_PRINCIPAL);
  });
});