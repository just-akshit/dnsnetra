from pathlib import Path
from typing import Dict, List, Optional


from .intel.manager import is_trusted
from .intel.malicious import is_malicious
from labeler.intel.reputation import store_malicious_domain
from .intel import ThreatIntelligence as OnlineThreatIntelligence
from labeler.intel.reputation import get_domain
from .intel.daily_review import get_daily_review_verdict


from .config import INTEL_DIR, LabelingConfig
from .logger import logger


class ThreatIntelligence:

    def __init__(self, config: LabelingConfig):
        self.config = config
        self.sets: dict[str, set[str]] = {}
        self.suspicious_tlds: set[str] = set()
        self._load_all_intel()
        self.online_intel = OnlineThreatIntelligence(
            config=self.config.get_online_ti_config(),
            db_store=store_malicious_domain,
            db_getter=get_domain,
        )
        logger.info("Threat Intelligence module initialized (offline mode).")

    def _load_file(self, filepath: Path) -> set[str]:
        if not filepath.exists():
            logger.warning("Intel file missing: %s", filepath.name)
            return set()


        try:
            with filepath.open("r", encoding="utf-8") as file:
                return {
                    line.strip().lower()
                    for line in file
                    if line.strip()
                    and not line.lstrip().startswith(("#", "//"))
                }
        except Exception:
            logger.exception("Failed to load %s", filepath.name)
            return set()

    def _load_all_intel(self) -> None:
        for source_name, info in self.config.INTEL_SOURCES.items():
            # Trusted domains are handled by the SQLite-backed Tranco database.
            if source_name == "whitelist":
                continue


            self.sets[source_name] = self._load_file(info["filepath"])


        self.suspicious_tlds = self._load_file(
            self.config.SUSPICIOUS_TLD_FILE
        )


        total_entries = sum(len(entries) for entries in self.sets.values())


        logger.info(
            "Loaded %d threat intelligence entries from local files.",
            total_entries,
        )

    def evaluate(
        self,
        domain: str,
        registered_domain: str = "",
        tld: str = "",
        response_code: str = "NOERROR",
        client_ip: Optional[str] = None,
        query_type: Optional[str] = None,
    ) -> tuple[int, list[str]]:


        score = 0
        reasons: list[str] = []

        full_domain = (domain or "").strip().lower().rstrip(".")
        rd = (registered_domain or "").strip().lower().rstrip(".")
        if not rd and full_domain:
            import tldextract
            ext = tldextract.extract(full_domain)
            rd = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or full_domain

        tld = (tld or "").strip().lower().rstrip(".")
        response_code = (response_code or "").strip().upper()

        # ------------------------------------------------------------------
        # STEP 1 — EXACT FQDN MALICIOUS MATCH (URLhaus)
        # ------------------------------------------------------------------
        # If the exact queried subdomain is listed in URLhaus, it is an
        # authoritative malicious hostname. This takes precedence even if the
        # parent/registered domain is in Tranco (e.g. evil.google.com).
        # (Apex exact matches where full_domain == rd are evaluated in Step 2/3).
        if full_domain and full_domain != rd and is_malicious(full_domain):
            urlhaus_metadata: dict = {
                "source": "URLHaus",
                "confidence": 1.0,
                "match_scope": "EXACT_FQDN",
                "matched_domain": full_domain,
            }
            if client_ip is not None:
                urlhaus_metadata["client_ip"] = client_ip
            if query_type is not None:
                urlhaus_metadata["query_type"] = query_type

            store_malicious_domain(full_domain, urlhaus_metadata)
            return (
                self.config.MAX_THREAT_SCORE,
                ["Known Malicious Domain (URLhaus)"],
            )

        # ------------------------------------------------------------------
        # STEP 2 — TRANCO POPULARITY CONTEXT
        # ------------------------------------------------------------------
        # If the registered domain or full domain is in Tranco, it is recognized
        # as popular benign context.
        # - Tranco is context, NOT proof of absolute security.
        # - It prevents URLhaus root-domain artifacts (e.g. google.com) from
        #   creating false malicious reputation or propagating to harmless subdomains.
        # - Malicious persistence is skipped entirely.
        if (rd and is_trusted(rd)) or (full_domain and is_trusted(full_domain)):
            return (
                self.config.WHITELIST_SCORE,
                ["Trusted Tranco Domain"],
            )

        # ------------------------------------------------------------------
        # STEP 3 — UNTRUSTED REGISTERED DOMAIN FALLBACK (URLhaus)
        # ------------------------------------------------------------------
        # If the registered domain is NOT in Tranco, but IS listed in URLhaus,
        # then the apex domain is a known malicious domain (e.g. a dedicated C2).
        # Subdomains inherit malicious classification from the untrusted apex.
        if rd and is_malicious(rd):
            target_domain = full_domain if full_domain else rd
            scope = "EXACT_FQDN" if full_domain == rd else "REGISTERED_DOMAIN"
            urlhaus_metadata: dict = {
                "source": "URLHaus",
                "confidence": 1.0,
                "match_scope": scope,
                "matched_domain": rd,
            }
            if client_ip is not None:
                urlhaus_metadata["client_ip"] = client_ip
            if query_type is not None:
                urlhaus_metadata["query_type"] = query_type

            store_malicious_domain(target_domain, urlhaus_metadata)
            return (
                self.config.MAX_THREAT_SCORE,
                ["Known Malicious Domain (URLhaus)"],
            )

        # ------------------------------------------------------------------
        # STEP 4 — REPUTATION DATABASE CACHE HIT
        # ------------------------------------------------------------------
        # If the domain was previously identified and cached in reputation_db,
        # return the cached verdict.
        rep_record = get_domain(full_domain) or (get_domain(rd) if rd else None)
        if rep_record and rep_record.get("status") == "malicious":
            return (
                self.config.MAX_THREAT_SCORE,
                [f"Reputation Cache Match ({rep_record.get('source', 'reputation_db')})"],
            )

        # ------------------------------------------------------------------
        # STEP 5 — DAILY REVIEW DATABASE HIT
        # ------------------------------------------------------------------
        # If the domain already exists in daily_review_db, reuse its stored
        # review state rather than reprocessing through external APIs.
        dr_record = get_daily_review_verdict(full_domain) or (get_daily_review_verdict(rd) if rd else None)
        if dr_record:
            dr_status = (dr_record.get("status") or "").lower()
            if dr_status == "malicious":
                return (
                    self.config.MAX_THREAT_SCORE,
                    ["Daily Review Match (malicious)"],
                )
            elif dr_status == "clean":
                return (
                    0,
                    ["Daily Review Match (clean)"],
                )
            else:
                return (
                    0,
                    ["Daily Review Match (review_needed)"],
                )


        # ------------------------------------------------------------------
        # Legacy offline intelligence files
        # ------------------------------------------------------------------
        for source_name, info in self.config.INTEL_SOURCES.items():
            if source_name == "whitelist":
                continue


            lookup_key = rd or full_domain
            if lookup_key and lookup_key in self.sets.get(source_name, set()):
                score += info["score"]
                reasons.append(info["reason"])
                break


        # ------------------------------------------------------------------
        # Suspicious TLD
        # ------------------------------------------------------------------
        if tld and tld in self.suspicious_tlds:
            score += self.config.SUSPICIOUS_TLD_SCORE
            reasons.append("Suspicious TLD")


        # ------------------------------------------------------------------
        # DNS Response Code
        # ------------------------------------------------------------------
        if response_code == "NXDOMAIN":
            score += self.config.NXDOMAIN_SCORE
            reasons.append("NXDOMAIN")
        elif response_code == "SERVFAIL":
            score += self.config.SERVFAIL_SCORE
            reasons.append("SERVFAIL")

        return score, reasons

    def close(self) -> None:
        """Release online threat intelligence resources."""
        self.online_intel.close()