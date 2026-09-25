import {
  normalizeDomainInput,
  isValidDomainStructure,
  isIpAddress,
  validateDomainSearchInput,
} from "../domain-utils";
import { MAIN_NAV_SECTIONS, getActiveNavItemId } from "../navigation";

function assert(condition: boolean, msg: string) {
  if (!condition) {
    throw new Error(`Assertion failed: ${msg}`);
  }
}

console.log("Running Domain Search & Navigation Unit Tests...\n");

// 1. Normalization Tests
console.log("1. Testing domain normalization...");
assert(normalizeDomainInput("google.com") === "google.com", "standard domain");
assert(normalizeDomainInput("GOOGLE.COM") === "google.com", "uppercase domain");
assert(normalizeDomainInput("  google.com  ") === "google.com", "whitespace padded");
assert(normalizeDomainInput("google.com.") === "google.com", "trailing FQDN dot");
assert(normalizeDomainInput(" Google.com. ") === "google.com", "mixed case, whitespace, trailing dot");
assert(normalizeDomainInput("https://google.com") === "google.com", "https url");
assert(normalizeDomainInput("http://google.com/search?q=test") === "google.com", "http url with query and path");
assert(normalizeDomainInput("https://google.com:443/path#hash") === "google.com", "https url with port and hash");
assert(normalizeDomainInput("example.com:8080") === "example.com", "domain with port");
assert(normalizeDomainInput("sub.domain.example.com") === "sub.domain.example.com", "subdomain");
assert(normalizeDomainInput("xn--fsqu00a.xn--4gbrim") === "xn--fsqu00a.xn--4gbrim", "punycode domain");
console.log("  ✓ Normalization passed");

// 2. Structural Domain Validation (No Hardcoded TLD list)
console.log("2. Testing structural domain validation...");
assert(isValidDomainStructure("google.com"), "google.com valid");
assert(isValidDomainStructure("example.org"), "example.org valid");
assert(isValidDomainStructure("sub.dept.company.co.uk"), "nested subdomain valid");
assert(isValidDomainStructure("example.internal"), "internal domain valid without TLD allowlist");
assert(isValidDomainStructure("something.test"), "test domain valid");
assert(isValidDomainStructure("foo.local"), "local domain valid");
assert(isValidDomainStructure("corp.lan"), "lan domain valid");
assert(isValidDomainStructure("xn--e1afmkfd.xn--p1ai"), "punycode domain valid");

// Invalid domain structures
assert(!isValidDomainStructure(""), "empty string invalid");
assert(!isValidDomainStructure("   "), "whitespace invalid");
assert(!isValidDomainStructure("invalid"), "single label without dot invalid");
assert(!isValidDomainStructure(".invalid"), "leading dot invalid");
assert(!isValidDomainStructure("invalid..com"), "consecutive dots invalid");
assert(!isValidDomainStructure("-bad.com"), "leading hyphen in label invalid");
assert(!isValidDomainStructure("bad-.com"), "trailing hyphen in label invalid");
assert(!isValidDomainStructure("bad..com"), "empty label invalid");
assert(!isValidDomainStructure("invalid domain.com"), "spaces inside domain invalid");
assert(!isValidDomainStructure("192.168.1.1"), "pure numeric IP is not domain");
assert(!isValidDomainStructure("google.123"), "pure numeric TLD invalid");
assert(!isValidDomainStructure("a".repeat(64) + ".com"), "label over 63 chars invalid");
console.log("  ✓ Structural validation passed");

// 3. IP Address Detection
console.log("3. Testing IP address detection...");
assert(isIpAddress("192.168.1.1"), "standard IPv4");
assert(isIpAddress("10.0.4.88"), "private IPv4");
assert(isIpAddress("127.0.0.1"), "loopback IPv4");
assert(!isIpAddress("256.1.1.1"), "invalid octet > 255");
assert(!isIpAddress("1.2.3"), "incomplete IPv4");
assert(isIpAddress("::1"), "loopback IPv6");
assert(isIpAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), "full IPv6");
assert(isIpAddress("2001:db8::1"), "compressed IPv6");
assert(!isIpAddress("google.com"), "domain is not IP");
console.log("  ✓ IP detection passed");

// 4. Combined Input Validation & Routing Differentiation
console.log("4. Testing validateDomainSearchInput...");
// Valid domain
const resDomain = validateDomainSearchInput("  GOOGLE.COM. ");
assert(resDomain.valid === true, "valid domain");
assert(resDomain.normalized === "google.com", "normalized domain");
assert(resDomain.isIp === false, "isIp is false");

// Valid IP
const resIp = validateDomainSearchInput("192.168.1.104");
assert(resIp.valid === true, "valid IP");
assert(resIp.normalized === "192.168.1.104", "normalized IP");
assert(resIp.isIp === true, "isIp is true");

// Invalid input
const resInvalidEmpty = validateDomainSearchInput("");
assert(resInvalidEmpty.valid === false, "empty is invalid");
assert(resInvalidEmpty.error === "Please enter a valid domain.", "empty error message");

const resInvalidWhitespace = validateDomainSearchInput("   ");
assert(resInvalidWhitespace.valid === false, "whitespace is invalid");

const resInvalidStructure = validateDomainSearchInput("not a valid domain!");
assert(resInvalidStructure.valid === false, "malformed is invalid");
assert(resInvalidStructure.error === "Please enter a valid domain.", "malformed error message");
console.log("  ✓ validateDomainSearchInput passed");

// 5. Navigation Configuration Tests
console.log("5. Testing navigation configuration...");
const analyticsSection = MAIN_NAV_SECTIONS.find((s) => s.id === "analytics");
assert(!!analyticsSection, "analytics section exists");
assert(
  !analyticsSection!.items.some((item) => item.id === "dns-analytics"),
  "DNS Analytics is removed from MAIN_NAV_SECTIONS"
);
assert(
  analyticsSection!.items.some((item) => item.id === "threat-analytics"),
  "Threat Analytics is present in MAIN_NAV_SECTIONS"
);

// Active Nav Item Resolution
assert(getActiveNavItemId("/analytics") === "threat-analytics", "/analytics maps to threat-analytics");
assert(getActiveNavItemId("/analytics/threats") === "threat-analytics", "/analytics/threats maps to threat-analytics");
assert(getActiveNavItemId("/analytics/dns") !== "dns-analytics", "/analytics/dns does not set fake active sidebar item");
console.log("  ✓ Navigation tests passed");

console.log("\nALL TESTS PASSED SUCCESSFULLY! ✓");
