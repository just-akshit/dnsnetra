import { describe, it, expect } from "vitest"
import { parseEntityQuery } from "@/lib/search/entity"

describe("parseEntityQuery", () => {
  it("accepts plain domains and lowercases them", () => {
    expect(parseEntityQuery("  Example.COM.  ")).toEqual({
      kind: "domain",
      value: "example.com",
    })
  })

  it("strips scheme, path, query and port", () => {
    expect(parseEntityQuery("https://example.com:8443/a/b?x=1")).toEqual({
      kind: "domain",
      value: "example.com",
    })
  })

  it("classifies IPv4 and IPv6 addresses as IPs", () => {
    expect(parseEntityQuery("192.168.1.10")).toEqual({
      kind: "ip",
      value: "192.168.1.10",
    })
    expect(parseEntityQuery("[2001:db8::1]")).toEqual({
      kind: "ip",
      value: "2001:db8::1",
    })
    expect(parseEntityQuery("2001:db8::1")).toEqual({
      kind: "ip",
      value: "2001:db8::1",
    })
  })

  it("rejects malformed or empty input", () => {
    expect(parseEntityQuery("").kind).toBe("invalid")
    expect(parseEntityQuery("not a domain").kind).toBe("invalid")
    expect(parseEntityQuery("192.168.1.999").kind).toBe("invalid")
    expect(parseEntityQuery("-broken.com").kind).toBe("invalid")
  })
})
