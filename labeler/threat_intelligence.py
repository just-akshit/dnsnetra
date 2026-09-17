from pathlib import Path
from typing import Dict, List, Optional


from .intel.manager import is_trusted
from .intel.malicious import is_malicious
from labeler.intel.reputation import store_malicious_domain
from .intel import ThreatIntelligence as OnlineThreatIntelligence
from labeler.intel.reputation import get_domain


from .config import INTEL_DIR, LabelingConfig
from .logger import logger
from .pipeline import DetectionPipeline, DetectionVerdict


class ThreatIntelligence:

    def __init__(self, config: LabelingConfig):
        self.config = config
        self.sets: dict[str, set[str]] = {}
        self.suspicious_tlds: set[str] = set()
        self._load_all_intel()
        self.pipeline = DetectionPipeline(config=self.config)
        self.online_intel = OnlineThreatIntelligence(
            config=self.config.get_online_ti_config(),
            db_store=store_malicious_domain,
            db_getter=get_domain,
        )
        logger.info("Threat Intelligence module initialized with DetectionPipeline.")

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
        registered_domain: str,
        tld: str,
        response_code: str,
        client_ip: Optional[str] = None,
        query_type: Optional[str] = None,
    ) -> tuple[int, list[str]]:
        """Evaluate domain through the multi-tier DetectionPipeline."""
        verdict = self.pipeline.evaluate(
            domain=domain,
            registered_domain=registered_domain,
            tld=tld,
            response_code=response_code,
            client_ip=client_ip,
            query_type=query_type,
        )
        return verdict.threat_score, verdict.reasons

    def evaluate_verdict(
        self,
        domain: str,
        registered_domain: str,
        tld: str,
        response_code: str,
        client_ip: Optional[str] = None,
        query_type: Optional[str] = None,
    ) -> DetectionVerdict:
        """Return the rich DetectionVerdict object for this domain."""
        return self.pipeline.evaluate(
            domain=domain,
            registered_domain=registered_domain,
            tld=tld,
            response_code=response_code,
            client_ip=client_ip,
            query_type=query_type,
        )

    def close(self) -> None:
        """Release threat intelligence resources."""
        self.pipeline.close()
        self.online_intel.close()