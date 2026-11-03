import { render, screen, waitFor } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"
import UsersPage from "./page"

vi.mock("@/lib/admin/users-api", () => ({
  AdminApiError: class AdminApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
  usersApi: {
    list: vi.fn().mockResolvedValue({
      total: 1, limit: 200, offset: 0,
      items: [{
        id: 7, username: "new.analyst", role: "ANALYST", status: "PENDING", is_active: false,
      }],
    }),
    approve: vi.fn().mockResolvedValue({ message: "ok" }),
  },
}))

vi.mock("@/components/auth/AuthGuard", () => ({
  useAuthUser: () => ({ username: "admin", role: "ADMIN" }),
}))

describe("UsersPage", () => {
  it("shows pending accounts", async () => {
    render(<UsersPage />)
    await waitFor(() => expect(screen.getByText("new.analyst")).toBeInTheDocument())
  })

  it("shows the pending section heading with count", async () => {
    render(<UsersPage />)
    await waitFor(() => expect(screen.getByText(/Pending approval/)).toBeInTheDocument())
  })
})
