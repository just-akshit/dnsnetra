import { afterEach, describe, expect, it, vi } from "vitest"
import { usersApi, AdminApiError } from "@/lib/admin/users-api"

// Suppress getActiveApiBase resolution — we just need a string prefix.
vi.mock("@/lib/auth/api", () => ({ getActiveApiBase: () => "http://localhost:8000" }))

describe("usersApi", () => {
  afterEach(() => vi.restoreAllMocks())

  it("lists users with query parameters", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ total: 0, limit: 50, offset: 0, items: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    )
    await usersApi.list({ status: "PENDING", limit: 25 })
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).toContain("/api/v1/users?")
    expect(url).toContain("status=PENDING")
    expect(url).toContain("limit=25")
  })

  it("omits empty params from query string", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ total: 0, limit: 50, offset: 0, items: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    )
    await usersApi.list()
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).not.toContain("?")
  })

  it("raises AdminApiError on 403", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ detail: "Forbidden" }), { status: 403 })
    )
    await expect(usersApi.list()).rejects.toMatchObject({ status: 403 })
    await expect(usersApi.list()).rejects.toBeInstanceOf(AdminApiError)
  })

  it("sends JSON body on create", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: 1, username: "bob", role: "ANALYST", status: "ACTIVE", is_active: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    )
    await usersApi.create({ username: "bob", password: "Pwd123!", role: "ANALYST", status: "ACTIVE" })
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect(init.method).toBe("POST")
    expect(JSON.parse(init.body as string)).toMatchObject({ username: "bob" })
  })
})
