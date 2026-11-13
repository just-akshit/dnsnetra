import * as React from "react"
import { describe, it, expect, vi } from "vitest"
import { render, screen } from "@testing-library/react"
import { Button } from "@/components/ui/button"
import { DataTableDetailDrawer } from "@/components/data-table/data-table-detail-drawer"
import Link from "next/link"

describe("Button & Link semantics", () => {
  it("renders a standard button with nativeButton semantics", () => {
    render(<Button>Click me</Button>)
    const button = screen.getByRole("button", { name: "Click me" })
    expect(button.tagName).toBe("BUTTON")
  })

  it("automatically infers nativeButton=false when render prop is an anchor/Link", () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {})

    render(
      <Button render={<Link href="/profile" />}>
        <span>Profile Link</span>
      </Button>
    )

    const baseUiErrors = errorSpy.mock.calls.filter((call) =>
      call.some((arg) => typeof arg === "string" && arg.includes("A component that acts as a button expected a native <button>"))
    )

    errorSpy.mockRestore()
    expect(baseUiErrors).toHaveLength(0)
  })

  it("renders DataTableDetailDrawer without Base UI nativeButton errors", () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {})

    render(
      <DataTableDetailDrawer
        open={true}
        onOpenChange={() => {}}
        entity={{ type: "client", id: "192.168.1.50", label: "192.168.1.50" }}
      >
        <div>Client Drawer Content</div>
      </DataTableDetailDrawer>
    )

    const baseUiErrors = errorSpy.mock.calls.filter((call) =>
      call.some((arg) => typeof arg === "string" && arg.includes("A component that acts as a button expected a native <button>"))
    )

    errorSpy.mockRestore()
    expect(baseUiErrors).toHaveLength(0)
    expect(screen.getByText(/full profile/i)).toBeDefined()
  })
})
