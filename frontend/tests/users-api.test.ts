import { afterEach, describe, expect, it, vi } from "vitest"
import { usersApi, AdminApiError } from "@/lib/admin/users-api"

vi.mock("@/lib/auth/api", () => ({ getActiveApiBase: () => "http://localhost:8000" }))

/** Returns a resolved 200 fetch mock with the given body. */
function ok(body: unknown) {
  return vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  )
}

/** Returns a rejected fetch mock with the given status and detail message. */
function err(status: number, detail: unknown = "error") {
  return vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify({ detail }), { status })
  )
}

describe("usersApi", () => {
  afterEach(() => vi.restoreAllMocks())

  // ── list ────────────────────────────────────────────────────────────────────

  it("lists users with query parameters", async () => {
    const fetchMock = ok({ total: 0, limit: 50, offset: 0, items: [] })
    await usersApi.list({ status: "PENDING", limit: 25 })
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).toContain("/api/v1/users?")
    expect(url).toContain("status=PENDING")
    expect(url).toContain("limit=25")
  })

  it("omits empty params from query string", async () => {
    const fetchMock = ok({ total: 0, limit: 50, offset: 0, items: [] })
    await usersApi.list()
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).not.toContain("?")
  })

  // ── error handling ───────────────────────────────────────────────────────────

  it("raises AdminApiError on 403 with correct status", async () => {
    err(403, "Forbidden")
    await expect(usersApi.list()).rejects.toBeInstanceOf(AdminApiError)
    err(403, "Forbidden")
    await expect(usersApi.list()).rejects.toMatchObject({ status: 403 })
  })

  it("includes server detail message in the error", async () => {
    err(422, "Username already taken")
    await expect(usersApi.create({ username: "x", password: "p", role: "ANALYST", status: "ACTIVE" }))
      .rejects.toThrow("Username already taken")
  })

  it("turns FastAPI validation detail arrays into readable messages", async () => {
    err(422, [
      {
        type: "string_too_short",
        loc: ["body", "password"],
        msg: "String should have at least 8 characters",
      },
    ])
    await expect(usersApi.create({ username: "x", password: "p", role: "ANALYST", status: "ACTIVE" }))
      .rejects.toThrow("password: String should have at least 8 characters")
  })

  it("falls back to generic message when detail is missing", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("{}", { status: 500 })
    )
    await expect(usersApi.list()).rejects.toThrow("Request failed (500)")
  })

  // ── create ───────────────────────────────────────────────────────────────────

  it("sends JSON body on create", async () => {
    const fetchMock = ok({ id: 1, username: "bob", role: "ANALYST", status: "ACTIVE", is_active: true })
    await usersApi.create({ username: "bob", password: "Pwd123!", role: "ANALYST", status: "ACTIVE" })
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect(init.method).toBe("POST")
    expect(JSON.parse(init.body as string)).toMatchObject({ username: "bob" })
  })

  // ── approve ──────────────────────────────────────────────────────────────────

  it("approve sends POST to /approve with role in body", async () => {
    const fetchMock = ok({ message: "approved" })
    await usersApi.approve(7, "ANALYST")
    const url = String(fetchMock.mock.calls[0][0])
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect(url).toContain("/api/v1/users/7/approve")
    expect(init.method).toBe("POST")
    expect(JSON.parse(init.body as string)).toEqual({ role: "ANALYST" })
  })

  // ── disable / enable / revokeSessions ────────────────────────────────────────

  it("disable sends POST to /disable", async () => {
    const fetchMock = ok({ message: "disabled" })
    await usersApi.disable(3)
    const url = String(fetchMock.mock.calls[0][0])
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect(url).toContain("/api/v1/users/3/disable")
    expect(init.method).toBe("POST")
  })

  it("enable sends POST to /enable", async () => {
    const fetchMock = ok({ message: "enabled" })
    await usersApi.enable(4)
    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/users/4/enable")
  })

  it("revokeSessions sends POST to /revoke-sessions", async () => {
    const fetchMock = ok({ message: "revoked", revoked_count: 2 })
    const result = await usersApi.revokeSessions(5)
    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/users/5/revoke-sessions")
    expect(result.revoked_count).toBe(2)
  })

  // ── update ───────────────────────────────────────────────────────────────────

  it("update sends PATCH with partial body", async () => {
    const fetchMock = ok({ id: 2, username: "alice", role: "SUPPORT", status: "ACTIVE", is_active: true })
    await usersApi.update(2, { role: "SUPPORT" })
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect(init.method).toBe("PATCH")
    expect(JSON.parse(init.body as string)).toEqual({ role: "SUPPORT" })
  })

  // ── resetPassword ────────────────────────────────────────────────────────────

  it("resetPassword sends no body and returns the one-time password", async () => {
    const fetchMock = ok({
      username: "u",
      temporary_password: "Tmp123!",
      must_change_password: true,
    })
    const result = await usersApi.resetPassword(9)
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/users/9/reset-password")
    expect(init.method).toBe("POST")
    expect(init.body).toBeUndefined()
    expect(result.temporary_password).toBe("Tmp123!")
  })

  // ── resetCode ────────────────────────────────────────────────────────────────

  it("resetCode sends POST and returns the code", async () => {
    const fetchMock = ok({ code: "abc123", expires_at: "2026-01-01T00:00:00Z" })
    const result = await usersApi.resetCode(11)
    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/users/11/reset-code")
    expect((fetchMock.mock.calls[0][1] as RequestInit).method).toBe("POST")
    expect(result.code).toBe("abc123")
  })
})

