"""
investigation/live/verdict.py
=============================
Four-state verdict for a live indicator.

Rules
-----
* Only providers that returned real data may vote.
* Absence of data is ``unknown`` — never ``clean``.
* VirusTotal drives ``malicious``; one detection in a broad scan is treated
  as a low-signal outlier, and OTX pulses alone never convict.
* A newly registered domain is never called ``clean`` on thin evidence.

The state and the confidence are deliberately separate: a result can be
``malicious`` with low confidence when only one weak source spoke.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from investigation.enrichment.models import DomainRegistrationResult
from investigation.live.models import IndicatorVerdict, ProviderEvidence

# VirusTotal detection-ratio bands.
VT_MALICIOUS_RATIO = 0.10
VT_MIN_ENGINES_MALICIOUS = 20
VT_SUSPICIOUS_ENGINES = 3
VT_MIN_ENGINES_CLEAN = 10
# A broad scan with zero detections outranks noisy OTX pulse references.
VT_STRONG_CLEAN_ENGINES = 50

# A domain younger than this with thin scan coverage is not "clean".
NEW_DOMAIN_DAYS = 14
NEW_DOMAIN_MIN_ENGINES = 20


def _age_days(registration: Optional[DomainRegistrationResult]) -> Optional[int]:
    created = getattr(registration, "created_at", None) if registration else None
    if not created:
        return None
    try:
        parsed = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - parsed).days)
    except (TypeError, ValueError):
        return None


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def evaluate_verdict(
    providers: List[ProviderEvidence],
    registration: Optional[DomainRegistrationResult] = None,
) -> IndicatorVerdict:
    """Combine provider evidence into a four-state verdict."""
    reasons: List[str] = []
    sources_with_data = 0
    vt_total = 0
    vt_malicious = False
    vt_suspicious = False
    vt_clean = False
    vt_malicious_strength = 0.0
    vt_suspicious_strength = 0.0
    otx_pulses = 0

    for evidence in providers:
        if evidence.status != "ok":
            continue

        if evidence.provider == "VirusTotal":
            total = evidence.total
            if total <= 0:
                continue
            sources_with_data += 1
            vt_total = max(vt_total, total)
            ratio = evidence.malicious / total

            if total >= VT_MIN_ENGINES_MALICIOUS and ratio >= VT_MALICIOUS_RATIO:
                vt_malicious = True
                vt_malicious_strength = max(
                    vt_malicious_strength,
                    _clamp(ratio / 0.25),
                )
                reasons.append(
                    f"VirusTotal: {evidence.malicious}/{total} engines flagged this indicator as malicious."
                )
            elif evidence.malicious >= 2 or ratio >= 0.02 or evidence.suspicious >= VT_SUSPICIOUS_ENGINES:
                vt_suspicious = True
                vt_suspicious_strength = max(
                    vt_suspicious_strength,
                    _clamp(ratio / VT_MALICIOUS_RATIO if ratio else 0.5),
                )
                if evidence.malicious > 0:
                    reasons.append(
                        f"VirusTotal: {evidence.malicious}/{total} engines flagged this indicator "
                        "as malicious (below the malicious threshold)."
                    )
                else:
                    reasons.append(
                        f"VirusTotal: {evidence.suspicious} engines flagged this indicator as suspicious."
                    )
            elif total >= VT_MIN_ENGINES_CLEAN:
                vt_clean = True
                if evidence.malicious == 1:
                    reasons.append(
                        f"VirusTotal: 1/{total} engine flagged this indicator; treated as a "
                        "low-signal outlier."
                    )
                else:
                    reasons.append(
                        f"VirusTotal: 0/{total} engines flagged this indicator."
                    )

        elif evidence.provider == "AlienVault OTX":
            sources_with_data += 1
            otx_pulses = max(otx_pulses, evidence.pulse_count)
            if evidence.pulse_count > 0:
                reasons.append(
                    f"AlienVault OTX: referenced by {evidence.pulse_count} threat pulse(s)."
                )
            else:
                reasons.append("AlienVault OTX: no threat pulses found.")

    # VirusTotal drives a malicious verdict; OTX only corroborates or adds
    # suspicion. OTX pulse counts on their own are far too noisy to convict a
    # legitimate domain (e.g. apple.com appears in many unrelated pulses).
    if vt_malicious:
        state = "malicious"
        confidence = _clamp(
            max(0.5, vt_malicious_strength + (0.1 if otx_pulses > 0 else 0.0))
        )
    elif vt_suspicious:
        state = "suspicious"
        confidence = _clamp(0.35 + 0.4 * vt_suspicious_strength)
    elif vt_clean and vt_total >= VT_STRONG_CLEAN_ENGINES:
        state = "clean"
        confidence = _clamp(0.3 + 0.4 * _clamp(vt_total / 50.0))
        if otx_pulses > 0:
            reasons.append(
                f"OTX references {otx_pulses} pulse(s), but VirusTotal's "
                f"{vt_total}-engine clean scan takes precedence."
            )
    elif otx_pulses > 0:
        state = "suspicious"
        confidence = _clamp(0.35 + 0.4 * _clamp(otx_pulses / 5.0))
        reasons.append(
            "Only OTX references this indicator; no corroborating VirusTotal detections."
        )
    elif vt_clean:
        state = "clean"
        confidence = _clamp(0.3 + 0.4 * _clamp(vt_total / 50.0))
    else:
        state = "unknown"
        confidence = 0.0
        reasons.append(
            "No provider returned usable scan or pulse data for this indicator."
        )

    age_days = _age_days(registration)

    # A young domain with thin scan coverage must not be presented as clean.
    if state == "clean" and age_days is not None and age_days < NEW_DOMAIN_DAYS:
        if vt_total < NEW_DOMAIN_MIN_ENGINES:
            state = "unknown"
            confidence = 0.0
            reasons.append(
                f"Registered {age_days} day(s) ago with only {vt_total} engine(s) of "
                "scan history — not enough evidence to call it clean."
            )

    if state == "unknown" and age_days is not None and age_days < 30:
        reasons.append(
            f"Registered {age_days} day(s) ago — limited historical reputation."
        )

    return IndicatorVerdict(
        state=state,
        confidence=round(confidence, 4),
        reasons=reasons,
        sources_with_data=sources_with_data,
        sources_queried=len(providers),
    )
