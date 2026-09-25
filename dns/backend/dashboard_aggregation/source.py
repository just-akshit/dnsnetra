"""
Normalized dashboard source — load once, validate, normalize, expose to all aggregations.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

REQUIRED_COLUMNS = {"domain", "client_ip", "label"}


@dataclass
class NormalizedDashboardSource:
    """Single normalized dataset for one aggregation run."""

    df: pd.DataFrame
    source_type: str
    source_path: str
    source_row_count: int
    duplicate_event_ids: int = 0
    feature_df: pd.DataFrame | None = None
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def from_csv(
        cls,
        path: Path,
        source_type: str = "batch",
        feature_matrix_path: Path | None = None,
    ) -> NormalizedDashboardSource:
        if not path.exists():
            raise FileNotFoundError(f"Labelled dataset not found: {path}")

        raw = pd.read_csv(path)
        warnings: list[str] = []

        missing = REQUIRED_COLUMNS - set(raw.columns)
        if missing:
            raise ValueError(f"Missing required columns: {sorted(missing)}")

        df = raw.copy()
        dup_count = 0
        if "event_id" in df.columns:
            dup_count = int(df.duplicated(subset=["event_id"], keep="last").sum())
            if dup_count:
                df = df.drop_duplicates(subset=["event_id"], keep="last")
                warnings.append(f"Dropped {dup_count} duplicate event_id rows")

        # Timestamps
        if "timestamp_iso8601" in df.columns:
            df["_ts"] = pd.to_datetime(df["timestamp_iso8601"], errors="coerce", utc=True)
        elif "timestamp" in df.columns:
            df["_ts"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        else:
            df["_ts"] = pd.NaT
            warnings.append("No timestamp column; timeline fields will be empty")

        df["_ts_str"] = df["_ts"].dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ").str.replace(r"000Z$", "Z", regex=True)
        df["time_bucket"] = df["_ts"].dt.strftime("%Y-%m-%d %H:00")

        # Labels
        df["label_norm"] = df["label"].astype(str).str.strip().str.lower()
        df["threat_score"] = pd.to_numeric(df.get("threat_score"), errors="coerce").fillna(0)
        df["confidence"] = pd.to_numeric(df.get("confidence"), errors="coerce").fillna(0)
        df["label_reason"] = df.get("label_reason", pd.Series([""] * len(df))).fillna("").astype(str)
        df["ti_source"] = df.get("ti_source", pd.Series(["unknown"] * len(df))).fillna("unknown").astype(str)
        df["query_type"] = df.get("query_type", pd.Series(["UNKNOWN"] * len(df))).fillna("UNKNOWN").astype(str)
        df["response_code"] = df.get("response_code", pd.Series(["UNKNOWN"] * len(df))).fillna("UNKNOWN").astype(str)
        df["resolved_ip"] = df.get("resolved_ip", pd.Series([""] * len(df))).fillna("").astype(str)

        df["_is_malicious"] = df["label_norm"].eq("malicious") | (df["threat_score"] >= 50)
        df["_is_suspicious"] = (
            df["label_norm"].eq("suspicious")
            | ((df["threat_score"] >= 30) & (df["threat_score"] < 50) & ~df["_is_malicious"])
        )
        df["_is_clean"] = df["label_norm"].eq("benign") & ~df["_is_malicious"] & ~df["_is_suspicious"]
        df["_is_unknown"] = df["ti_source"].eq("unknown") & ~df["_is_malicious"] & ~df["_is_suspicious"] & ~df["_is_clean"]
        df["_is_threat"] = df["_is_malicious"] | df["_is_suspicious"]

        feature_df = None
        if feature_matrix_path and feature_matrix_path.exists():
            feature_df = pd.read_csv(feature_matrix_path)
            if "domain" in feature_df.columns:
                feature_df = feature_df.drop_duplicates(subset=["domain"], keep="last")
            else:
                warnings.append("Feature matrix missing domain column")
                feature_df = None

        return cls(
            df=df,
            source_type=source_type,
            source_path=str(path),
            source_row_count=len(raw),
            duplicate_event_ids=dup_count,
            feature_df=feature_df,
            warnings=warnings,
        )


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), default=str)


def breakdown(series: pd.Series) -> dict[str, int]:
    counts = series.value_counts()
    return {str(k): int(v) for k, v in counts.items()}
