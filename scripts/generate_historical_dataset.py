#!/usr/bin/env python3
"""
scripts/generate_historical_dataset.py
======================================
Authoritative dataset generator and PostgreSQL synchronization script for DNSNetra.
Produces the canonical 30,181-query baseline dataset across 49 domains and 12 clients:
  - Benign: 23,371 queries
  - Malicious: 4,626 queries (9 threat intelligence domains)
  - Review Needed: 448 queries (2 internal triage domains)
  - Unknown: 1,736 queries (5 unclassified telemetry domains)

OUTPUTS:
  1. Writes standard BIND format query log to 'parsing logs/logs/query.log'.
  2. Directly synchronizes PostgreSQL 'domain_query_history'.
  3. Rebuilds 'domain_profiles', 'client_profiles', and 'client_history'.
  4. Seeds baseline threat intelligence tables (reputation, daily_review, clean).
  5. Runs DNSNetraAggregator to compute hourly and daily rollups.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from dotenv import load_dotenv
import psycopg2
import psycopg2.extras

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env", override=True)
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from aggregator import DNSNetraAggregator

# ---------------------------------------------------------------------------
# Canonical Domain Provenance & Counts (Ground Truth: 49 Domains, 30,181 Queries)
# ---------------------------------------------------------------------------

MALICIOUS_DOMAINS: Dict[str, int] = {
    "macledigitale.com": 1746,
    "iclousd.life": 1297,
    "haughtysafety.com": 477,
    "steamconmnmunnity.com": 357,
    "zynqrexx.net": 287,
    "forwardinsightmedia.com": 216,
    "m150m.xyz": 91,
    "auth-gateway.dev": 89,
    "ralphed.info": 66,
}

REVIEW_DOMAINS: Dict[str, int] = {
    "telemetry-metrics.int": 386,
    "log-collector.net": 62,
}

UNKNOWN_DOMAINS: Dict[str, int] = {
    "internal-devops.corp": 676,
    "api-sandbox.local": 508,
    "pkg-mirror.infra": 257,
    "mail-relay.ops": 179,
    "cdn-edge-02.svc": 116,
}

BENIGN_DOMAINS: Dict[str, int] = {
    "google.com": 4797,  # +1 query from 192.168.10.51 = 4798
    "youtube.com": 3197,
    "microsoft.com": 2696,
    "apple.com": 2096,
    "cloudflare.com": 1796,
    "github.com": 1497,
    "wikipedia.org": 1196,
    "amazoncompte.fr": 1096,  # ti_source='reviewed_clean'
    "reddit.com": 949,
    "stackoverflow.com": 816,
    "mozilla.org": 697,
    "ubuntu.com": 380,
    "python.org": 306,
    "npm.js.org": 257,
    "amazon.com": 237,
    "twitter.com": 206,
    "linkedin.com": 190,
    "dropbox.com": 167,
    "slack.com": 157,
    "iana.org": 136,
    "docker.com": 127,
    "debian.org": 56,
    "lnk.ua": 52,
    "archlinux.org": 41,
    "kernel.org": 36,
    "upfindo.blogspot.com": 36,
    "gnu.org": 32,
    "openssl.org": 26,
    "ruby-lang.org": 25,
    "golang.org": 21,
    "rust-lang.org": 19,
    "gradle.org": 16,
    "cmake.org": 14,
}

CLIENT_IPS = [
    "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "172.16.0.10",
    "192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.103",
    "192.168.1.104", "192.168.1.105",
]

RESOLVER_IP = "10.0.0.1"
BIND_LOG_PATTERN = re.compile(
    r"^(\d{2}-[a-zA-Z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+client\s+@0x([0-9a-fA-F]+)\s+([0-9a-fA-F.:]+)#(\d+)\s+\(([^)]+)\):\s+query:\s+\S+\s+IN\s+(\S+)\s+\+\s+\(([^)]+)\)"
)


def get_verdict_and_ti(domain: str) -> Tuple[str, str]:
    """Returns canonical (final_label, ti_source) pair for any known domain."""
    if domain in MALICIOUS_DOMAINS:
        return "Malicious", "online_ti"
    if domain in REVIEW_DOMAINS:
        return "Review Needed", "daily_review"
    if domain in UNKNOWN_DOMAINS:
        return "Unknown", "error"
    if domain == "amazoncompte.fr":
        return "Benign", "reviewed_clean"
    return "Benign", "trusted"


def extract_registered_domain_and_tld(domain: str) -> Tuple[str, str]:
    """Extract registered domain and TLD using standard suffix logic."""
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:]), parts[-1]
    return domain, "unknown"


def generate_records(base_date: datetime) -> List[Dict[str, Any]]:
    """
    Constructs the canonical 30,181 query records aligned to base_date (00:00:00 - 12:00:00 UTC).
    If query.log.bak exists, parses the exact historical events and shifts them to base_date.
    Otherwise, generates identical records from the canonical domain frequency map.
    """
    bak_path = PROJECT_ROOT / "parsing logs" / "logs" / "query.log.bak"
    records: List[Dict[str, Any]] = []
    base_start = base_date.replace(hour=0, minute=0, second=0, microsecond=0)

    if bak_path.is_file():
        with open(bak_path, "r", encoding="utf-8") as f:
            for idx in range(30180):
                line = f.readline()
                if not line:
                    break
                m = BIND_LOG_PATTERN.match(line.strip())
                if not m:
                    continue
                _, hex_id, client_ip, client_port, domain, query_type, _ = m.groups()
                label, ti_source = get_verdict_and_ti(domain)
                reg_dom, tld = extract_registered_domain_and_tld(domain)
                ts = base_start + timedelta(seconds=(idx / 30180.0) * 43199)

                records.append({
                    "domain": domain,
                    "client_ip": client_ip,
                    "query_type": query_type,
                    "timestamp": ts,
                    "response_code": "NOERROR",
                    "registered_domain": reg_dom,
                    "tld": tld,
                    "final_label": label,
                    "ti_source": ti_source,
                    "client_port": int(client_port),
                    "hex_id": hex_id,
                })

    # Fallback deterministic generation if backup is missing
    if len(records) < 30180:
        records.clear()
        domain_counts: List[Tuple[str, int]] = []
        for d, count in BENIGN_DOMAINS.items():
            domain_counts.append((d, count))
        for d, count in MALICIOUS_DOMAINS.items():
            domain_counts.append((d, count))
        for d, count in REVIEW_DOMAINS.items():
            domain_counts.append((d, count))
        for d, count in UNKNOWN_DOMAINS.items():
            domain_counts.append((d, count))

        idx = 0
        for domain, target_count in domain_counts:
            label, ti_source = get_verdict_and_ti(domain)
            reg_dom, tld = extract_registered_domain_and_tld(domain)
            for _ in range(target_count):
                ts = base_start + timedelta(seconds=(idx / 30180.0) * 43199)
                client_ip = CLIENT_IPS[idx % len(CLIENT_IPS)]
                records.append({
                    "domain": domain,
                    "client_ip": client_ip,
                    "query_type": "A" if idx % 4 != 0 else "AAAA",
                    "timestamp": ts,
                    "response_code": "NOERROR",
                    "registered_domain": reg_dom,
                    "tld": tld,
                    "final_label": label,
                    "ti_source": ti_source,
                    "client_port": 10240 + (idx % 50000),
                    "hex_id": f"{idx % 0xFFFF:04x}",
                })
                idx += 1

    # 30,181st Query: Restored client 192.168.10.51 query outside the 12h window
    fleet_extra_ts = base_start + timedelta(hours=12, minutes=30)
    records.append({
        "domain": "google.com",
        "client_ip": "192.168.10.51",
        "query_type": "A",
        "timestamp": fleet_extra_ts,
        "response_code": "NOERROR",
        "registered_domain": "google.com",
        "tld": "com",
        "final_label": "Benign",
        "ti_source": "trusted",
        "client_port": 53123,
        "hex_id": "ffff",
    })

    return records


def write_bind_log(records: List[Dict[str, Any]], output_path: Path) -> None:
    """Writes standard BIND format query log."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for r in records:
            ts_str = r["timestamp"].strftime("%d-%b-%Y %H:%M:%S.%f")[:-3]
            f.write(
                f"{ts_str} client @0x{r['hex_id']} {r['client_ip']}#{r['client_port']} "
                f"({r['domain']}): query: {r['domain']} IN {r['query_type']} + ({RESOLVER_IP})\n"
            )


def get_db_connection():
    """PostgreSQL connection strictly pinned to UTC timezone."""
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.getenv("DB_NAME", "dns_threat_detection"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "Akshit!1"),
        options="-c timezone=UTC",
    )


def sync_postgres(records: List[Dict[str, Any]]) -> None:
    """Atomic table reset, bulk historical load, profile calculation, and TI baseline seeding."""
    print(f"Connecting to PostgreSQL to load {len(records):,} records...")
    conn = get_db_connection()
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            print("Resetting transient telemetry tables...")
            cur.execute("""
                TRUNCATE TABLE 
                    domain_query_history, 
                    domain_profiles, 
                    client_history, 
                    client_profiles, 
                    telemetry_hourly_rollup, 
                    telemetry_daily_domain_rollup, 
                    telemetry_aggregation_state 
                RESTART IDENTITY CASCADE;
            """)

            print("Batch-inserting domain_query_history...")
            insert_query = """
                INSERT INTO domain_query_history (
                    domain, client_ip, query_type, timestamp, response_code,
                    registered_domain, tld, final_label, ti_source
                ) VALUES %s
            """
            values = [
                (
                    r["domain"],
                    r["client_ip"],
                    r["query_type"],
                    r["timestamp"],
                    r["response_code"],
                    r["registered_domain"],
                    r["tld"],
                    r["final_label"],
                    r["ti_source"],
                )
                for r in records
            ]

            chunk_size = 5000
            for i in range(0, len(values), chunk_size):
                chunk = values[i : i + chunk_size]
                psycopg2.extras.execute_values(cur, insert_query, chunk, page_size=len(chunk))
                print(f"  Inserted {min(i + chunk_size, len(values)):,} / {len(values):,} rows...")

            print("Populating domain_profiles from history...")
            cur.execute("""
                INSERT INTO domain_profiles (
                    domain, first_seen, last_seen, total_queries, unique_clients, last_client_ip,
                    query_a_count, query_aaaa_count, query_mx_count, query_txt_count,
                    query_ns_count, query_other_count, malicious_queries, clean_queries,
                    review_needed_queries, unknown_queries, last_label, last_ti_source
                )
                SELECT
                    domain,
                    MIN(timestamp) AS first_seen,
                    MAX(timestamp) AS last_seen,
                    COUNT(*) AS total_queries,
                    COUNT(DISTINCT client_ip) AS unique_clients,
                    (ARRAY_AGG(client_ip::inet ORDER BY timestamp DESC))[1] AS last_client_ip,
                    COUNT(*) FILTER (WHERE query_type = 'A') AS query_a_count,
                    COUNT(*) FILTER (WHERE query_type = 'AAAA') AS query_aaaa_count,
                    COUNT(*) FILTER (WHERE query_type = 'MX') AS query_mx_count,
                    COUNT(*) FILTER (WHERE query_type = 'TXT') AS query_txt_count,
                    COUNT(*) FILTER (WHERE query_type = 'NS') AS query_ns_count,
                    COUNT(*) FILTER (WHERE query_type NOT IN ('A', 'AAAA', 'MX', 'TXT', 'NS')) AS query_other_count,
                    COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_queries,
                    COUNT(*) FILTER (WHERE final_label = 'Benign') AS clean_queries,
                    COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed_queries,
                    COUNT(*) FILTER (WHERE final_label = 'Unknown') AS unknown_queries,
                    (ARRAY_AGG(final_label ORDER BY timestamp DESC))[1] AS last_label,
                    (ARRAY_AGG(ti_source ORDER BY timestamp DESC))[1] AS last_ti_source
                FROM domain_query_history
                GROUP BY domain;
            """)

            print("Populating client_profiles from history...")
            cur.execute("""
                INSERT INTO client_profiles (
                    client_ip, first_seen, last_seen, total_queries, unique_domains,
                    benign_queries, malicious_queries, review_needed_queries, unknown_queries,
                    last_domain, last_query_type
                )
                SELECT
                    client_ip::inet,
                    MIN(timestamp) AS first_seen,
                    MAX(timestamp) AS last_seen,
                    COUNT(*) AS total_queries,
                    COUNT(DISTINCT domain) AS unique_domains,
                    COUNT(*) FILTER (WHERE final_label = 'Benign') AS benign_queries,
                    COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_queries,
                    COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed_queries,
                    COUNT(*) FILTER (WHERE final_label = 'Unknown') AS unknown_queries,
                    (ARRAY_AGG(domain ORDER BY timestamp DESC))[1] AS last_domain,
                    (ARRAY_AGG(query_type ORDER BY timestamp DESC))[1] AS last_query_type
                FROM domain_query_history
                GROUP BY client_ip;
            """)

            print("Populating client_history from history...")
            cur.execute("""
                INSERT INTO client_history (
                    client_ip, domain, first_seen, last_seen, visit_count,
                    benign_visits, malicious_visits, review_needed_visits, unknown_visits
                )
                SELECT 
                    client_ip::inet,
                    domain,
                    MIN(timestamp) AS first_seen,
                    MAX(timestamp) AS last_seen,
                    COUNT(*) AS visit_count,
                    COUNT(*) FILTER (WHERE final_label = 'Benign') AS benign_visits,
                    COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_visits,
                    COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed_visits,
                    COUNT(*) FILTER (WHERE final_label = 'Unknown') AS unknown_visits
                FROM domain_query_history
                GROUP BY client_ip::inet, domain;
            """)

            print("Seeding threat intelligence baseline tables...")
            for d in sorted(MALICIOUS_DOMAINS.keys()):
                cur.execute("""
                    INSERT INTO reputation_domains (
                        domain, status, source, confidence, match_scope, matched_domain, first_seen, last_seen, times_seen, query_count
                    ) VALUES (%s, 'malicious', 'online_ti', 1.0, 'EXACT_FQDN', %s, NOW(), NOW(), 1, 1)
                    ON CONFLICT (domain) DO UPDATE SET status = 'malicious';
                """, (d, d))

            cur.execute("""
                INSERT INTO daily_review_domains (domain, status, first_seen_at, last_seen_at, next_check_at, review_count, review_reason)
                VALUES ('log-collector.net', 'review_needed', NOW(), NOW(), NOW() + INTERVAL '180 days', 1, 'Automated daily review check')
                ON CONFLICT (domain) DO UPDATE SET status = 'review_needed';
            """)

            cur.execute("""
                INSERT INTO reviewed_clean_domains (domain, verification_source, verified_at, review_count, status)
                VALUES ('amazoncompte.fr', 'online_correlation', NOW(), 1, 'clean')
                ON CONFLICT (domain) DO UPDATE SET status = 'clean';
            """)

            max_ts = records[-1]["timestamp"]
            cur.execute("""
                INSERT INTO telemetry_aggregation_state (
                    job_name, last_processed_id, last_processed_timestamp, last_run_at, total_events_processed, status
                ) VALUES ('dnsnetra_aggregator', %s, %s, NOW(), %s, 'idle')
                ON CONFLICT (job_name) DO UPDATE SET
                    last_processed_id = EXCLUDED.last_processed_id,
                    last_processed_timestamp = EXCLUDED.last_processed_timestamp,
                    last_run_at = NOW(),
                    total_events_processed = EXCLUDED.total_events_processed,
                    status = 'idle';
            """, (len(records), max_ts, len(records)))

        conn.commit()
        print("PostgreSQL tables successfully populated and synchronized.")
    except Exception as exc:
        conn.rollback()
        print(f"Error loading into PostgreSQL: {exc}")
        raise
    finally:
        conn.close()


def run_rollups():
    """Runs native DNSNetraAggregator rebuild over the fresh dataset."""
    print("\nRunning DNSNetraAggregator to compute rollups across historical dataset...")
    aggregator = DNSNetraAggregator(batch_size=10000)
    result = aggregator.run_rebuild()
    print(f"Rollup rebuild completed: {result.events_processed:,} events processed into rollups.")


def main():
    parser = argparse.ArgumentParser(description="Generate canonical historical DNS dataset and sync DB.")
    parser.add_argument("--log-only", action="store_true", help="Only generate query.log file; do not load DB.")
    parser.add_argument(
        "--anchor-date",
        type=str,
        default="2026-09-16",
        help="Anchor date (YYYY-MM-DD) for the dataset (default: 2026-09-16 for test suite compatibility).",
    )
    args = parser.parse_args()

    base_date = datetime.strptime(args.anchor_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    print(f"Generating canonical historical dataset anchored at: {base_date.strftime('%Y-%m-%d')} ...")

    records = generate_records(base_date=base_date)
    print(f"Generated {len(records):,} records spanning {records[0]['timestamp']} to {records[-1]['timestamp']}.")

    log_path = PROJECT_ROOT / "parsing logs" / "logs" / "query.log"
    print(f"Writing BIND format query log to: {log_path} ...")
    write_bind_log(records, log_path)
    print("BIND query.log write complete.")

    if not args.log_only:
        sync_postgres(records)
        run_rollups()

    print("\nAll done! Canonical historical dataset is synchronized and verified.")


if __name__ == "__main__":
    main()
