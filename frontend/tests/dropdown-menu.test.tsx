import * as React from "react"
import { describe, it, expect, vi } from "vitest"
import { render, screen, fireEvent } from "@testing-library/react"
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuLabel,
  DropdownMenuItem,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
} from "@/components/ui/dropdown-menu"
import { DataTableFilter } from "@/components/data-table/data-table-filter"
import type { TableFilterConfig } from "@/lib/data-table/types"

describe("DropdownMenu & DropdownMenuLabel", () => {
  it("renders DropdownMenuLabel standalone outside DropdownMenuGroup without error", () => {
    expect(() => {
      render(
        <DropdownMenu open={true}>
          <DropdownMenuTrigger>Open Menu</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuLabel>Standalone Label</DropdownMenuLabel>
            <DropdownMenuItem>Item 1</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )
    }).not.toThrow()

    expect(screen.getByText("Standalone Label")).toBeInTheDocument()
    expect(screen.getByText("Standalone Label")).toHaveAttribute("data-slot", "dropdown-menu-label")
  })

  it("renders DropdownMenuLabel inside DropdownMenuGroup without error", () => {
    expect(() => {
      render(
        <DropdownMenu open={true}>
          <DropdownMenuTrigger>Open Menu</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuGroup>
              <DropdownMenuLabel>Group Header</DropdownMenuLabel>
              <DropdownMenuItem>Group Item 1</DropdownMenuItem>
            </DropdownMenuGroup>
          </DropdownMenuContent>
        </DropdownMenu>
      )
    }).not.toThrow()

    expect(screen.getByText("Group Header")).toBeInTheDocument()
    expect(screen.getByText("Group Header")).toHaveAttribute("data-slot", "dropdown-menu-label")
  })

  it("renders DropdownMenuLabel inside DropdownMenuRadioGroup without error", () => {
    expect(() => {
      render(
        <DropdownMenu open={true}>
          <DropdownMenuTrigger>Open Menu</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuRadioGroup value="opt1">
              <DropdownMenuLabel>Radio Header</DropdownMenuLabel>
              <DropdownMenuRadioItem value="opt1">Option 1</DropdownMenuRadioItem>
            </DropdownMenuRadioGroup>
          </DropdownMenuContent>
        </DropdownMenu>
      )
    }).not.toThrow()

    expect(screen.getByText("Radio Header")).toBeInTheDocument()
  })

  it("renders DataTableFilter and allows selecting a verdict without MenuGroupContext error", () => {
    const verdictFilterConfig: TableFilterConfig = {
      id: "verdict",
      title: "Verdict",
      options: [
        { label: "Clean / Benign", value: "Benign" },
        { label: "Malicious", value: "Malicious" },
        { label: "Review Needed", value: "Review Needed" },
        { label: "Unknown", value: "Unknown" },
      ],
    }

    const handleChange = vi.fn()

    const { getByRole, getByText, getAllByText } = render(
      <DataTableFilter
        config={verdictFilterConfig}
        value={undefined}
        onChange={handleChange}
      />
    )

    // Trigger button should be rendered
    const trigger = getByRole("button")
    expect(trigger).toHaveTextContent("Verdict")

    // Clicking trigger opens the dropdown
    fireEvent.click(trigger)

    // Label should be in the document (in trigger and in menu label)
    expect(getAllByText("Verdict").length).toBeGreaterThanOrEqual(2)

    // Options should be visible
    expect(getByText("Clean / Benign")).toBeInTheDocument()
    expect(getByText("Malicious")).toBeInTheDocument()
    expect(getByText("Review Needed")).toBeInTheDocument()
    expect(getByText("Unknown")).toBeInTheDocument()

    // Clicking "Malicious" calls onChange
    fireEvent.click(getByText("Malicious"))
    expect(handleChange).toHaveBeenCalledWith("Malicious")
  })
})
