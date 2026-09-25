from pathlib import Path
from dotenv import load_dotenv

# Load the same API configuration used by the live pipeline.
PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / "api.env")

from labeler.config import LabelingConfig
from labeler.intel.providers.virustotal import VirusTotalProvider
from labeler.intel.providers.alienvault import AlienVaultOTXProvider


DOMAIN = "google.com"

config = LabelingConfig()

online_config = config.get_online_ti_config()

print("=" * 60)
print("DNS THREAT DETECTION — ONLINE TI TEST")
print("=" * 60)

print()
print("Configuration:")
print("  VirusTotal enabled:", online_config["ENABLE_VT"])
print("  OTX enabled:", online_config["ENABLE_OTX"])
print(
    "  VirusTotal API key:",
    "CONFIGURED" if online_config["VT_API_KEY"] or online_config["VT_API_KEYS"] else "MISSING",
)
print(
    "  OTX API key:",
    "CONFIGURED" if online_config["OTX_API_KEY"] or online_config["OTX_API_KEYS"] else "MISSING",
)

print()
print("Testing domain:", DOMAIN)
print()

# -------------------------
# VirusTotal
# -------------------------

print("[1] VirusTotal")
print("-" * 40)

vt = VirusTotalProvider(online_config)

if not vt.is_enabled():
    print("SKIPPED — VirusTotal disabled")
else:
    result = vt.lookup(DOMAIN)

    print("Provider      :", result.provider)
    print("Unavailable   :", result.unavailable)
    print("Found         :", result.found)
    print("Malicious     :", result.malicious)
    print("Confidence    :", result.confidence)
    print("Malicious cnt :", result.malicious_count)
    print("Harmless cnt  :", result.harmless_count)
    print("Suspicious cnt:", result.suspicious_count)
    print("Error         :", result.error)

vt.close()

print()

# -------------------------
# AlienVault OTX
# -------------------------

print("[2] AlienVault OTX")
print("-" * 40)

otx = AlienVaultOTXProvider(online_config)

if not otx.is_enabled():
    print("SKIPPED — OTX disabled")
else:
    result = otx.lookup(DOMAIN)

    print("Provider      :", result.provider)
    print("Unavailable   :", result.unavailable)
    print("Found         :", result.found)
    print("Malicious     :", result.malicious)
    print("Confidence    :", result.confidence)
    print("Malicious cnt :", result.malicious_count)
    print("Harmless cnt  :", result.harmless_count)
    print("Suspicious cnt:", result.suspicious_count)
    print("Error         :", result.error)

otx.close()

print()
print("=" * 60)
print("ONLINE TI TEST COMPLETE")
print("=" * 60)