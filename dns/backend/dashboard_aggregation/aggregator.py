"""
Dashboard Aggregator Implementation
===================================
Reads row-level datasets from CSVs and PostgreSQL database, pre-computes summary metrics,
and updates SQLite `dashboard.db`.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from .config import (
    DASHBOARD_DB_PATH,
    FEATURE_MATRIX_PATH,
    LABELLED_DATASET_PATH,
    PG_HOST,
    PG_NAME,
    PG_PASSWORD,
    PG_PORT,
    PG_USER,
)
from .schema import initialize_dashboard_db

logger = logging.getLogger(__name__)


class DashboardAggregator:
    """
    Aggregates threat detection metrics into pre-computed summary tables in `dashboard.db`.
    """

    def __init__(
        self,
        dashboard_db_path: Path = DASHBOARD_DB_PATH,
        labelled_dataset_path: Path = LABELLED_DATASET_PATH,
        feature_matrix_path: Path = FEATURE_MATRIX_PATH,
    ) -> None:
        self.dashboard_db_path = dashboard_db_path
        self.labelled_dataset_path = labelled_dataset_path
        self.feature_matrix_path = feature_matrix_path

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def _get_sqlite_connection(self) -> sqlite3.Connection:
        """Returns a connection to dashboard.db."""
        conn = sqlite3.connect(self.dashboard_db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _get_pg_connection(self) -> Any | None:
        """Attempts to connect to PostgreSQL. Returns None if connection fails."""
        try:
            import psycopg

            conn = psycopg.connect(
                host=PG_HOST,
                port=PG_PORT,
                dbname=PG_NAME,
                user=PG_USER,
                password=PG_PASSWORD,
                connect_timeout=5,
            )
            return conn
        except ImportError as e:
            logger.warning("psycopg module not found. PostgreSQL connection unavailable: %s", e)
            return None
        except psycopg.Error as e:
            logger.warning("PostgreSQL connection unavailable for aggregation: %s", e)
            return None

    # ------------------------------------------------------------------
    # Per-table aggregation methods
    # ------------------------------------------------------------------

    def aggregate_metrics_summary(self, df: pd.DataFrame) -> dict[str, Any]:
        """Computes single-row metrics summary snapshot."""
        total_queries = len(df)
        if total_queries == 0:
            return {
                "total_queries": 0,
                "total_threats": 0,
                "threats_blocked_pct": 0.0,
                "unique_clients": 0,
                "unique_domains": 0,
                "last_pipeline_run_at": datetime.now(timezone.utc).isoformat(),
            }

        is_malicious = (
            df["label"].astype(str).str.lower().eq("malicious")
            | (df["threat_score"].fillna(0) >= 50)
        )
        total_threats = int(is_malicious.sum())
        threats_blocked_pct = round((total_threats / total_queries) * 100.0, 2)
        unique_clients = int(df["client_ip"].nunique()) if "client_ip" in df.columns else 0
        unique_domains = int(df["domain"].nunique()) if "domain" in df.columns else 0
        last_run = datetime.now(timezone.utc).isoformat()

        summary = {
            "total_queries": total_queries,
            "total_threats": total_threats,
            "threats_blocked_pct": threats_blocked_pct,
            "unique_clients": unique_clients,
            "unique_domains": unique_domains,
            "last_pipeline_run_at": last_run,
        }

        with self._get_sqlite_connection() as conn:
            conn.execute(
                """
                INSERT INTO metrics_summary
                    (id, total_queries, total_threats, threats_blocked_pct,
                     unique_clients, unique_domains, last_pipeline_run_at)
                VALUES
                    (1, :total_queries, :total_threats, :threats_blocked_pct,
                     :unique_clients, :unique_domains, :last_pipeline_run_at)
                ON CONFLICT(id) DO UPDATE SET
                    total_queries      = metrics_summary.total_queries + excluded.total_queries,
                    total_threats      = metrics_summary.total_threats + excluded.total_threats,
                    threats_blocked_pct = ROUND(CAST(metrics_summary.total_threats + excluded.total_threats AS REAL) / CAST(metrics_summary.total_queries + excluded.total_queries AS REAL) * 100.0, 2),
                    unique_clients     = metrics_summary.unique_clients + excluded.unique_clients,
                    unique_domains     = metrics_summary.unique_domains + excluded.unique_domains,
                    last_pipeline_run_at = excluded.last_pipeline_run_at
                """,
                summary,
            )
            conn.commit()

        logger.info("Updated metrics_summary: %s", summary)
        return summary

    def aggregate_threats_by_category(self, df: pd.DataFrame) -> int:
        """Computes threat breakdown by category/label_reason."""
        if df.empty:
            return 0

        cat_series = df["label_reason"].fillna(df["ti_source"]).fillna(df["label"]).astype(str)
        cat_counts = cat_series.value_counts().reset_index()
        cat_counts.columns = ["category", "count"]
        total_count = int(cat_counts["count"].sum())
        cat_counts["pct"] = (
            (cat_counts["count"] / total_count * 100.0).round(2)
            if total_count > 0
            else 0.0
        )

        records = cat_counts.to_dict(orient="records")

        with self._get_sqlite_connection() as conn:
            conn.executemany(
                """
                INSERT INTO threats_by_category (category, count, pct)
                VALUES (:category, :count, 0.0)
                ON CONFLICT(category) DO UPDATE SET
                    count = threats_by_category.count + excluded.count
                """,
                records,
            )
            
            # Recalculate percentages for all categories
            conn.execute(
                """
                UPDATE threats_by_category
                SET pct = ROUND(CAST(count AS REAL) / (SELECT SUM(count) FROM threats_by_category) * 100.0, 2)
                """
            )
            conn.commit()

        logger.info("Updated threats_by_category with %d records", len(records))
        return len(records)

    def aggregate_queries_timeseries(self, df: pd.DataFrame) -> int:
        """Computes hourly query timeseries."""
        if df.empty:
            return 0

        df = df.copy()

        if "timestamp_iso8601" in df.columns:
            ts_col = pd.to_datetime(df["timestamp_iso8601"], errors="coerce")
        elif "timestamp" in df.columns:
            ts_col = pd.to_datetime(df["timestamp"], errors="coerce")
        else:
            ts_col = pd.Series([datetime.now(timezone.utc)] * len(df))

        df["time_bucket"] = ts_col.dt.strftime("%Y-%m-%d %H:00")
        df["is_threat"] = (
            df["label"].astype(str).str.lower().eq("malicious")
            | (df["threat_score"].fillna(0) >= 50)
        ).astype(int)

        grouped = (
            df.groupby("time_bucket")
            .agg(total_queries=("domain", "count"), threat_queries=("is_threat", "sum"))
            .reset_index()
        )

        records = grouped.to_dict(orient="records")

        with self._get_sqlite_connection() as conn:
            conn.executemany(
                """
                INSERT INTO queries_timeseries (time_bucket, total_queries, threat_queries)
                VALUES (:time_bucket, :total_queries, :threat_queries)
                ON CONFLICT(time_bucket) DO UPDATE SET
                    total_queries = queries_timeseries.total_queries + excluded.total_queries,
                    threat_queries = queries_timeseries.threat_queries + excluded.threat_queries
                """,
                records,
            )
            conn.commit()

        logger.info("Updated queries_timeseries with %d time buckets", len(records))
        return len(records)

    def aggregate_geo_distribution(self, df: pd.DataFrame) -> int:
        """
        Computes country/ASN distribution.
        GeoIP is currently disabled (enable_geoip=False) — table stays empty unless
        the enrichment pipeline populates country/asn columns in future runs.
        """
        records = []
        if "asn" in df.columns and "country" in df.columns:
            geo_df = df.dropna(subset=["country"])
            if not geo_df.empty:
                grouped = (
                    geo_df.groupby(["country", "asn"])
                    .agg(
                        query_count=("domain", "count"),
                        threat_count=(
                            "label",
                            lambda s: int((s.astype(str).str.lower() == "malicious").sum()),
                        ),
                    )
                    .reset_index()
                )
                # Convert asn column to string for SQLite storage
                grouped["asn"] = grouped["asn"].astype(str)
                records = grouped.to_dict(orient="records")

        with self._get_sqlite_connection() as conn:
            conn.execute("DELETE FROM geo_distribution")
            if records:
                conn.executemany(
                    """
                    INSERT INTO geo_distribution (country, asn, query_count, threat_count)
                    VALUES (:country, :asn, :query_count, :threat_count)
                    """,
                    records,
                )
            conn.commit()

        if not records:
            logger.info(
                "geo_distribution is empty — GeoIP enrichment is currently disabled "
                "(enable_geoip=False in run_pipeline.py). Enable it to populate this table."
            )
        else:
            logger.info("Updated geo_distribution with %d records", len(records))
        return len(records)

    def aggregate_top_domains(self, df: pd.DataFrame) -> int:
        """Computes top requested domains by querying domain_profiles in Postgres."""
        records = []
        pg_conn = self._get_pg_connection()

        if pg_conn:
            import psycopg

            try:
                with pg_conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT
                            domain,
                            total_queries,
                            COALESCE(last_label, 'benign') as label,
                            COALESCE(last_ti_source, '') as ti_source,
                            last_seen::text
                        FROM domain_profiles
                        ORDER BY total_queries DESC
                        LIMIT 100
                        """
                    )
                    rows = cur.fetchall()
                    for r in rows:
                        domain, query_count, label, _ti_source, last_seen = r
                        threat_score = 100.0 if str(label).lower() == 'malicious' else 0.0
                        records.append(
                            {
                                "domain": domain,
                                "query_count": int(query_count),
                                "label": label,
                                "threat_score": threat_score,
                                "last_seen": str(last_seen),
                            }
                        )
                pg_conn.close()
            except psycopg.Error as e:
                logger.warning("PostgreSQL query failed for top_domains: %s", e)

        if not records:
            logger.warning("No top domains aggregated (PostgreSQL query returned no records or failed).")
            return 0

        with self._get_sqlite_connection() as conn:
            conn.execute("DELETE FROM top_domains")
            conn.executemany(
                """
                INSERT INTO top_domains (domain, query_count, label, threat_score, last_seen)
                VALUES (:domain, :query_count, :label, :threat_score, :last_seen)
                """,
                records,
            )
            conn.commit()

        logger.info("Updated top_domains with %d domains", len(records))
        return len(records)

    def aggregate_top_clients(self, df: pd.DataFrame) -> int:
        """
        Computes top client IPs by joining Postgres `client_profiles` + `client_history`.
        """
        records = []
        pg_conn = self._get_pg_connection()

        if pg_conn:
            import psycopg

            try:
                with pg_conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT
                            cp.client_ip::text,
                            COALESCE(SUM(ch.visit_count), 0) AS query_count,
                            COALESCE(cp.malicious_queries, 0) AS malicious_query_count,
                            cp.last_seen::text
                        FROM client_profiles cp
                        LEFT JOIN client_history ch ON cp.client_ip = ch.client_ip
                        GROUP BY cp.client_ip, cp.last_seen, cp.malicious_queries
                        ORDER BY query_count DESC
                        LIMIT 100
                        """
                    )
                    rows = cur.fetchall()
                    for r in rows:
                        client_ip, query_count, malicious_query_count, last_seen = r
                        records.append(
                            {
                                "client_ip": client_ip,
                                "query_count": int(query_count),
                                "malicious_query_count": int(malicious_query_count),
                                "last_seen": str(last_seen),
                            }
                        )
                pg_conn.close()
            except psycopg.Error as e:
                logger.warning(
                    "PostgreSQL query failed for top_clients: %s", e
                )

        if not records:
            logger.warning("No top clients aggregated (PostgreSQL query returned no records or failed).")
            return 0

        with self._get_sqlite_connection() as conn:
            conn.execute("DELETE FROM top_clients")
            conn.executemany(
                """
                INSERT INTO top_clients (client_ip, query_count, malicious_query_count, last_seen)
                VALUES (:client_ip, :query_count, :malicious_query_count, :last_seen)
                """,
                records,
            )
            conn.commit()

        logger.info("Updated top_clients with %d clients", len(records))
        return len(records)

    def aggregate_recent_flagged_domains(self, df: pd.DataFrame) -> int:
        """Computes recent flagged/malicious domains."""
        if df.empty:
            return 0

        is_flagged = (
            df["label"].astype(str).str.lower().ne("benign")
            | (df["threat_score"].fillna(0) >= 50)
        )
        flagged_df = df[is_flagged].copy()

        if flagged_df.empty:
            return 0

        ts_col = (
            "timestamp_iso8601"
            if "timestamp_iso8601" in flagged_df.columns
            else "timestamp"
        )
        flagged_df["flagged_at"] = flagged_df[ts_col].astype(str)
        flagged_df["label_reason"] = flagged_df["label_reason"].fillna(
            "Flagged by Threat Intelligence"
        )
        flagged_df["ti_source"] = flagged_df["ti_source"].fillna("Internal Engine")
        flagged_df["confidence"] = flagged_df["confidence"].fillna(100.0)

        flagged_df = flagged_df.sort_values(by=ts_col, ascending=False).head(50)

        records = flagged_df[
            ["domain", "label", "label_reason", "ti_source", "confidence", "flagged_at"]
        ].to_dict(orient="records")

        with self._get_sqlite_connection() as conn:
            conn.executemany(
                """
                INSERT INTO recent_flagged_domains
                    (domain, label, label_reason, ti_source, confidence, flagged_at)
                VALUES
                    (:domain, :label, :label_reason, :ti_source, :confidence, :flagged_at)
                """,
                records,
            )
            
            # Retention trim: delete records older than 7 days
            conn.execute(
                """
                DELETE FROM recent_flagged_domains 
                WHERE datetime(flagged_at) < datetime('now', '-7 days')
                """
            )
            conn.commit()

        logger.info("Updated recent_flagged_domains with %d records", len(records))
        return len(records)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run_all(self) -> dict[str, Any]:
        """
        Executes full aggregation pipeline reading input dataset and writing to `dashboard.db`.
        Returns summary of row counts per table.
        """
        logger.info("Dashboard Aggregation Started")
        initialize_dashboard_db(self.dashboard_db_path)

        if not self.labelled_dataset_path.exists():
            logger.warning(
                "Labelled dataset CSV not found at %s. Skipping aggregation.",
                self.labelled_dataset_path,
            )
            return {}

        df = pd.read_csv(self.labelled_dataset_path)
        logger.info("Loaded labelled dataset: %d rows, %d columns", len(df), len(df.columns))

        summary = self.aggregate_metrics_summary(df)
        cat_count = self.aggregate_threats_by_category(df)
        ts_count = self.aggregate_queries_timeseries(df)
        geo_count = self.aggregate_geo_distribution(df)
        domains_count = self.aggregate_top_domains(df)
        clients_count = self.aggregate_top_clients(df)
        flagged_count = self.aggregate_recent_flagged_domains(df)

        counts = {
            "metrics_summary": 1 if summary else 0,
            "threats_by_category": cat_count,
            "queries_timeseries": ts_count,
            "geo_distribution": geo_count,
            "top_domains": domains_count,
            "top_clients": clients_count,
            "recent_flagged_domains": flagged_count,
        }

        logger.info("Dashboard Aggregation Finished. Table row counts: %s", counts)

        # Print row counts for verification
        print("=" * 60)
        print("Dashboard Aggregation — Table Row Counts")
        print("=" * 60)
        for table, count in counts.items():
            print(f"  {table:30s} : {count}")
        print("=" * 60)

        return counts
