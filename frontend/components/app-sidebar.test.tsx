import * as React from "react"
import { render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { AppSidebar } from "./app-sidebar"
import { SidebarProvider } from "@/components/ui/sidebar"

const state = vi.hoisted(() => ({
  user: { username: "a", role: "ANALYST" as string },
}))

vi.mock("@/components/auth/AuthGuard", () => ({
  useAuthUser: () => state.user,
}))
vi.mock("@/lib/auth/api", () => ({ authApi: { logout: vi.fn().mockResolvedValue(undefined) } }))
vi.mock("@/hooks/use-mobile", () => ({ useIsMobile: () => false }))
vi.mock("next/navigation", () => ({
  usePathname: () => "/dashboard",
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
})

