import * as React from "react"
import { render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { AppSidebar } from "@/components/app-sidebar"
import { SidebarProvider } from "@/components/ui/sidebar"

const state = vi.hoisted(() => ({
  user: { username: "a", role: "ANALYST" as string },
  pathname: "/dashboard",
}))

vi.mock("@/components/auth/AuthGuard", () => ({
  useAuthUser: () => state.user,
}))
vi.mock("@/lib/auth/api", () => ({ authApi: { logout: vi.fn().mockResolvedValue(undefined) } }))
vi.mock("@/hooks/use-mobile", () => ({ useIsMobile: () => false }))
vi.mock("next/navigation", () => ({
  usePathname: () => state.pathname,
  useRouter: () => ({ replace: vi.fn() }),
}))
vi.mock("next/link", () => ({
  default: ({ href, children, ...props }: React.ComponentProps<"a">) =>
    React.createElement("a", { href, ...props }, children),
}))

function renderSidebar() {
  return render(
    <SidebarProvider>
      <AppSidebar />
    </SidebarProvider>
  )
}

describe("AppSidebar", () => {
  beforeEach(() => {
    state.user = { username: "a", role: "ANALYST" }
    state.pathname = "/dashboard"
  })

  it("hides Users from non-admins", () => {
    renderSidebar()
    expect(screen.queryByText("Users")).not.toBeInTheDocument()
  })

  it("shows Users to admins", () => {
    state.user = { username: "a", role: "ADMIN" }
    renderSidebar()
    expect(screen.getByText("Users")).toBeInTheDocument()
  })

  it("shows Users to super admins", () => {
    state.user = { username: "root", role: "SUPER_ADMIN" }
    renderSidebar()
    expect(screen.getByText("Users")).toBeInTheDocument()
  })

  it("marks only Saved Reports active on a saved report", () => {
    state.pathname = "/reports/saved"
    renderSidebar()

    expect(screen.getByRole("link", { name: "Saved Reports" })).toHaveAttribute(
      "data-active"
    )
    expect(screen.getByRole("link", { name: "Reports" })).not.toHaveAttribute(
      "data-active"
    )
  })
})

