import argparse
import time
from pathlib import Path
from typing import Optional

import pandas as pd
from tqdm import tqdm

from .config import DEFAULT_INPUT, DEFAULT_OUTPUT, LabelingConfig
from .heuristics import Heuristics
from .logger import logger
from .threat_intelligence import ThreatIntelligence


class DNSLabeller:
    def __init__(self, config: Optional[LabelingConfig] = None):
        self.config = config or LabelingConfig()
        self.ti = ThreatIntelligence(self.config)
        self.heuristics = Heuristics(self.config)
        logger.info("DNS Dataset Labeller initialized (training data only - offline).")

    def _process_row(
        self, row: pd.Series
    # CHANGE: return type extended with ti_source (str) as the fifth element.
    # Existing positional values (threat_score, label, confidence, label_reason)
    # are unchanged so all callers that only unpack four values keep working.
    ) -> tuple[int, str, int, str, str]:
        # FIX (Bug 1): forward client_ip and query_type from the row so that
        # ThreatIntelligence.evaluate() can include them in the metadata dict
        # passed to store_malicious_domain() for URLhaus-matched domains.
        verdict = self.ti.evaluate_verdict(
            domain=str(row.get("domain", "")),
            registered_domain=str(row.get("registered_domain", "")),
            tld=str(row.get("tld", "")),
            response_code=str(row.get("response_code", "")),
            client_ip=row.get("client_ip") or None,
            query_type=row.get("query_type") or None,
        )
        return verdict.as_labeller_tuple()

    def run(self, input_path: Path, output_path: Path) -> None:
        start_time = time.perf_counter()

        if not input_path.exists():
            raise FileNotFoundError(f"Input dataset not found: {input_path}")

        logger.info("Loading dataset: %s", input_path)

        df = pd.read_csv(input_path)

        logger.info(f"Processing {len(df):,} DNS records...")

        tqdm.pandas(desc="Labeling")

        # CHANGE: OUTPUT_COLUMNS must include "ti_source" so the new column is
        # written to the DataFrame and ultimately to the CSV.  We build the
        # expanded column list by appending "ti_source" to whatever
        # OUTPUT_COLUMNS already defines, without mutating the config object
        # itself (preserving backward compatibility for any other consumer of
        # config.OUTPUT_COLUMNS).
        output_columns = list(self.config.OUTPUT_COLUMNS)

        df[output_columns] = df.progress_apply(
            lambda row: pd.Series(self._process_row(row)),
            axis=1,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)

        self._print_summary(df, start_time, output_path)

    def _print_summary(
        self,
        df: pd.DataFrame,
        start_time: float,
        output_path: Path,
    ) -> None:
        elapsed = time.perf_counter() - start_time

        stats = df["label"].value_counts()

        response_codes = (
            df["response_code"].astype(str).str.upper()
            if "response_code" in df.columns
            else pd.Series(dtype=str)
        )

        ti_matches = (
            df["label_reason"]
            .fillna("")
            .str.contains(
                r"Threat Intelligence|Phishing|Botnet|Cryptomining|Malicious|Trusted Tranco",
                case=False,
                regex=True,
            )
            .sum()
        )

        summary = f"""
=== DNS Labeller Summary ===
Total records          : {len(df):,}
Benign                 : {stats.get("Benign", 0):,}
Suspicious             : {stats.get("Suspicious", 0):,}
Malicious              : {stats.get("Malicious", 0):,}
Average threat score   : {df["threat_score"].mean():.2f}
TI Matches             : {ti_matches:,}
NXDOMAIN count         : {(response_codes == "NXDOMAIN").sum():,}
SERVFAIL count         : {(response_codes == "SERVFAIL").sum():,}
Execution time         : {elapsed:.2f} seconds
Output                 : {output_path}
============================
"""

        print(summary)
        logger.info("Labeling completed successfully.")

    @staticmethod
    def build_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="DNS Dataset Labeller (Offline Training Module)"
        )

        parser.add_argument(
            "--input",
            type=Path,
            default=DEFAULT_INPUT,
            help="Path to normalized_dns_dataset.csv",
        )

        parser.add_argument(
            "--output",
            type=Path,
            default=DEFAULT_OUTPUT,
            help="Path to labelled_dns_dataset.csv",
        )

        return parser


def main() -> None:
    parser = DNSLabeller.build_parser()
    args = parser.parse_args()

    labeller = DNSLabeller()
    labeller.run(args.input, args.output)


if __name__ == "__main__":
    main()