import { describe, expect, it } from "vitest"
import { assignableRoles, canManage } from "@/lib/admin/permissions"

describe("role hierarchy mirror", () => {
  it("lets ADMIN manage staff only", () => {
    expect(canManage("ADMIN", { id: 2, role: "ANALYST" })).toBe(true)
    expect(canManage("ADMIN", { id: 2, role: "SUPPORT" })).toBe(true)
    expect(canManage("ADMIN", { id: 2, role: "ADMIN" })).toBe(false)
    expect(canManage("ADMIN", { id: 2, role: "SUPER_ADMIN" })).toBe(false)
  })

  it("lets SUPER_ADMIN manage everyone else but not self", () => {
    expect(canManage("SUPER_ADMIN", { id: 2, role: "ADMIN" }, 1)).toBe(true)
    expect(canManage("SUPER_ADMIN", { id: 2, role: "SUPER_ADMIN" }, 1)).toBe(true)
    expect(canManage("SUPER_ADMIN", { id: 1, role: "SUPER_ADMIN" }, 1)).toBe(false)
  })

  it("denies ANALYST and SUPPORT entirely", () => {
    expect(canManage("ANALYST", { id: 2, role: "ANALYST" })).toBe(false)
    expect(canManage("SUPPORT", { id: 2, role: "SUPPORT" })).toBe(false)
    expect(canManage(undefined, { id: 2, role: "ANALYST" })).toBe(false)
  })

  it("offers only assignable roles", () => {
    expect(assignableRoles("ADMIN")).toEqual(["ANALYST", "SUPPORT"])
    expect(assignableRoles("SUPER_ADMIN")).toEqual([
      "SUPER_ADMIN",
      "ADMIN",
      "ANALYST",
      "SUPPORT",
    ])
    expect(assignableRoles("ANALYST")).toEqual([])
  })
})
