import * as React from "react"
import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import { LiveIntelSection } from "@/components/intelligence/live-verdict"
import type { LiveIntelReport } from "@/lib/data-table/api-client"

function report(overrides: Partial<LiveIntelReport> = {}): LiveIntelReport {
  return {
    indicator: "example.com",
    kind: "domain",
    verdict: {
      state: "unknown",
      confidence: 0,
      reasons: [],
      sources_with_data: 0,
      sources_queried: 2,
    },
    providers: [],
    checked_at: "2026-11-08T00:00:00Z",
    ...overrides,
  }
}

describe("LiveIntelSection", () => {
  it("renders an unknown verdict without confusing it for clean", () => {
    render(
      <LiveIntelSection
        live={report({
          verdict: {
            state: "unknown",
            confidence: 0,
            reasons: ["No provider returned usable scan or pulse data for this indicator."],
            sources_with_data: 0,
            sources_queried: 2,
          },
        })}
        kind="domain"
        observedInNetwork={false}
      />
    )

    expect(screen.getByText("Unknown")).toBeInTheDocument()
    expect(screen.queryByText("Clean")).not.toBeInTheDocument()
    expect(
      screen.getByText(/No provider returned usable scan or pulse data/)
    ).toBeInTheDocument()
  })

  it("renders a malicious verdict and VirusTotal evidence", () => {
    render(
      <LiveIntelSection
        live={report({
          verdict: {
            state: "malicious",
            confidence: 0.92,
            reasons: ["VirusTotal: 12/90 engines flagged this indicator as malicious."],
            sources_with_data: 1,
            sources_queried: 1,
          },
          providers: [
            {
              provider: "VirusTotal",
              status: "ok",
              malicious: 12,
              suspicious: 0,
              harmless: 78,
              undetected: 0,
              total: 90,
              pulse_count: 0,
              confidence: 0.92,
              details: { reputation: -42 },
            },
          ],
        })}
        kind="domain"
        observedInNetwork
      />
    )

    expect(screen.getByText("Malicious")).toBeInTheDocument()
    expect(screen.getByText("92% confidence")).toBeInTheDocument()
    expect(screen.getByText("12/90")).toBeInTheDocument()
    expect(screen.getByText(/Also observed in this network/)).toBeInTheDocument()
  })

  it("shows a graceful note when live intel is unavailable", () => {
    render(
      <LiveIntelSection live={null} kind="domain" observedInNetwork={false} />
    )

    expect(
      screen.getByText(/Live external intelligence is temporarily unavailable/)
    ).toBeInTheDocument()
  })
})
