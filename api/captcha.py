"""
Self-Hosted CAPTCHA Engine for DNSNetra API
===========================================
Generates secure, self-hosted visual CAPTCHAs with distortion, noise,
and cryptographically signed challenges with replay and tampering protection.
Includes a pluggable CaptchaChallengeStore abstraction (default in-memory with bounded capacity).
No external network dependencies or third-party CAPTCHA providers.
"""

from __future__ import annotations

import abc
import base64
import hashlib
import hmac
import io
import math
import os
import random
import threading
import time
import uuid
from typing import Optional, Tuple

from PIL import Image, ImageDraw, ImageFont

CAPTCHA_SECRET_DEFAULT = "dnsnetra-dev-test-captcha-secret-key-do-not-use-in-production"
CAPTCHA_EXPIRY_SECONDS_DEFAULT = 300  # 5 minutes

# Unambiguous characters (avoiding 0/O, 1/I/l)
CAPTCHA_CHARACTERS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
CAPTCHA_LENGTH = 6


def get_captcha_secret() -> bytes:
    """Retrieve CAPTCHA signing secret from environment."""
    secret = os.getenv("AUTH_CAPTCHA_SECRET") or os.getenv("CAPTCHA_SECRET") or CAPTCHA_SECRET_DEFAULT
    return secret.encode("utf-8")


def normalize_captcha_answer(raw: Optional[str]) -> str:
    """
    Canonical answer normalization function used identically in both
    generation and verification paths.
    """
    if not raw:
        return ""
    return raw.strip().upper()


# ---------------------------------------------------------------------------
# Pluggable Challenge Store Abstraction
# ---------------------------------------------------------------------------

class BaseCaptchaStore(abc.ABC):
    """Abstract interface for CAPTCHA challenge storage and replay protection."""

    @abc.abstractmethod
    def issue(self, challenge_id: str, signature: str, expiry: float) -> None:
        """Record an issued CAPTCHA challenge signature and its expiration epoch."""
        pass

    @abc.abstractmethod
    def get(self, challenge_id: str) -> Optional[Tuple[str, float]]:
        """Retrieve (signature, expiry) for an issued challenge."""
        pass

    @abc.abstractmethod
    def is_consumed(self, challenge_id: str) -> bool:
        """Check whether a challenge has already been consumed."""
        pass

    @abc.abstractmethod
    def consume(self, challenge_id: str, expiry: float) -> bool:
        """
        Atomically mark a challenge as consumed.
        Returns True if consumed, or False if already consumed or absent.
        """
        pass

    @abc.abstractmethod
    def cleanup_expired(self) -> int:
        """Purge expired challenges and consumed markers to bound memory."""
        pass


class InMemoryCaptchaStore(BaseCaptchaStore):
    """
    Thread-safe, memory-bounded in-memory CAPTCHA store with automatic TTL eviction.
    """

    def __init__(self, max_capacity: int = 10000):
        self._lock = threading.Lock()
        self._issued: dict[str, tuple[str, float]] = {}  # cid -> (sig, expiry)
        self._consumed: dict[str, float] = {}  # cid -> expiry
        self._max_capacity = max_capacity

    def issue(self, challenge_id: str, signature: str, expiry: float) -> None:
        self.cleanup_expired()
        with self._lock:
            # Prevent unbounded memory growth under attack
            if len(self._issued) >= self._max_capacity:
                # Evict oldest 10% of entries
                sorted_keys = sorted(self._issued.keys(), key=lambda k: self._issued[k][1])
                for k in sorted_keys[: self._max_capacity // 10]:
                    self._issued.pop(k, None)

            self._issued[challenge_id] = (signature, expiry)

    def get(self, challenge_id: str) -> Optional[Tuple[str, float]]:
        with self._lock:
            return self._issued.get(challenge_id)

    def is_consumed(self, challenge_id: str) -> bool:
        with self._lock:
            return challenge_id in self._consumed

    def consume(self, challenge_id: str, expiry: float) -> bool:
        with self._lock:
            if challenge_id in self._consumed:
                return False
            self._issued.pop(challenge_id, None)
            self._consumed[challenge_id] = expiry
            return True

    def cleanup_expired(self) -> int:
        now = time.time()
        with self._lock:
            exp_issued = [k for k, (_, exp) in self._issued.items() if exp < now]
            for k in exp_issued:
                self._issued.pop(k, None)

            exp_consumed = [k for k, exp in self._consumed.items() if exp < now]
            for k in exp_consumed:
                self._consumed.pop(k, None)

            return len(exp_issued) + len(exp_consumed)


# Default global store instance (can be swapped in testing or future Redis integrations)
_GLOBAL_STORE: InMemoryCaptchaStore = InMemoryCaptchaStore()

# Backward-compatibility aliases for existing test harnesses
_ISSUED_CHALLENGES = _GLOBAL_STORE._issued
_CONSUMED_CHALLENGES = _GLOBAL_STORE._consumed


def get_captcha_store() -> BaseCaptchaStore:
    """Return the active CAPTCHA challenge store instance."""
    return _GLOBAL_STORE


def set_captcha_store(store: BaseCaptchaStore) -> None:
    """Set the active CAPTCHA challenge store instance (useful for testing or clustering)."""
    global _GLOBAL_STORE
    _GLOBAL_STORE = store


# ---------------------------------------------------------------------------
# Cryptographic Signing & Image Generation
# ---------------------------------------------------------------------------

def compute_challenge_signature(captcha_id: str, normalized_answer: str, exp: int) -> str:
    """Compute HMAC-SHA256 signature for challenge binding."""
    message = f"{captcha_id}:{normalized_answer}:{exp}".encode("utf-8")
    return hmac.new(get_captcha_secret(), message, hashlib.sha256).hexdigest()


_compute_challenge_signature = compute_challenge_signature


def generate_captcha_image(text: str, width: int = 240, height: int = 80) -> str:
    """
    Render visual CAPTCHA image with font rotation, noise lines, and distortion.
    Returns base64 data URI (data:image/png;base64,...).
    """
    bg_color = (random.randint(235, 250), random.randint(235, 250), random.randint(235, 250))
    image = Image.new("RGB", (width, height), bg_color)
    draw = ImageDraw.Draw(image)

    # 1. Background noise dots
    for _ in range(350):
        xy = (random.randint(0, width - 1), random.randint(0, height - 1))
        dot_color = (random.randint(140, 210), random.randint(140, 210), random.randint(140, 210))
        draw.point(xy, fill=dot_color)

    # 2. Random background noise lines
    for _ in range(6):
        start = (random.randint(0, width // 3), random.randint(0, height))
        end = (random.randint(width // 2, width), random.randint(0, height))
        line_color = (random.randint(100, 180), random.randint(100, 180), random.randint(100, 180))
        draw.line([start, end], fill=line_color, width=random.randint(1, 2))

    # 3. Draw characters with individual rotation and positioning
    font_paths = [
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    ]
    font = None
    for path in font_paths:
        if os.path.exists(path):
            try:
                font = ImageFont.truetype(path, size=34)
                break
            except Exception:
                continue
    if font is None:
        font = ImageFont.load_default()

    char_spacing = (width - 40) // len(text)
    for i, char in enumerate(text):
        char_img = Image.new("RGBA", (50, 50), (255, 255, 255, 0))
        char_draw = ImageDraw.Draw(char_img)
        char_color = (
            random.randint(15, 80),
            random.randint(15, 80),
            random.randint(30, 110),
            255,
        )
        char_draw.text((10, 5), char, font=font, fill=char_color)

        angle = random.uniform(-25, 25)
        rotated_char = char_img.rotate(angle, expand=1, resample=Image.Resampling.BILINEAR)

        x_pos = 20 + i * char_spacing + random.randint(-4, 4)
        y_pos = 12 + random.randint(-6, 6)
        image.paste(rotated_char, (x_pos, y_pos), mask=rotated_char)

    # 4. Foreground cross-cutting sine / noise curve
    curve_points = []
    frequency = random.uniform(0.03, 0.06)
    amplitude = random.uniform(8, 14)
    phase = random.uniform(0, 2 * math.pi)
    mid_y = height // 2
    for x in range(0, width, 2):
        y = mid_y + int(amplitude * math.sin(frequency * x + phase))
        curve_points.append((x, y))
    if len(curve_points) > 1:
        draw.line(curve_points, fill=(random.randint(80, 140), random.randint(80, 140), random.randint(80, 140)), width=2)

    buf = io.BytesIO()
    image.save(buf, format="PNG")
    b64_str = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64_str}"


def create_captcha(expires_in: int = CAPTCHA_EXPIRY_SECONDS_DEFAULT) -> dict[str, str | int]:
    """
    Generate a new CAPTCHA challenge:
    - Generates 6-character random text
    - Renders the image
    - Computes signed challenge token
    - Returns challenge metadata without plaintext answer
    """
    store = get_captcha_store()

    # Generate random text and normalize once
    answer = "".join(random.choice(CAPTCHA_CHARACTERS) for _ in range(CAPTCHA_LENGTH))
    normalized_answer = normalize_captcha_answer(answer)

    captcha_id = str(uuid.uuid4())
    expiry = int(time.time()) + expires_in
    signature = compute_challenge_signature(captcha_id, normalized_answer, expiry)

    # Issue challenge into store
    store.issue(captcha_id, signature, float(expiry))

    image_data_uri = generate_captcha_image(normalized_answer)

    return {
        "captcha_id": captcha_id,
        "image": image_data_uri,
        "expires_in": expires_in,
    }


def verify_and_consume_captcha(captcha_id: Optional[str], user_answer: Optional[str]) -> Tuple[bool, str]:
    """
    Verify CAPTCHA answer and consume challenge to prevent replay:
    - Validates presence of captcha_id and user_answer
    - Checks against replay (is_consumed)
    - Checks challenge existence in store
    - Checks expiration
    - Verifies HMAC signature using constant-time compare_digest
    - Consumes the challenge atomically

    Returns:
        (True, "OK") if verified successfully.
        (False, error_reason) if verification failed.
    """
    if not captcha_id or not user_answer:
        return False, "CAPTCHA ID and answer are required"

    # Validate UUID format
    try:
        uuid.UUID(str(captcha_id).strip())
    except (ValueError, AttributeError):
        return False, "CAPTCHA challenge not found or invalid"

    store = get_captcha_store()

    # 1. Check if already consumed (Replay Attack)
    if store.is_consumed(captcha_id):
        return False, "CAPTCHA challenge has already been used"

    # 2. Check if challenge was issued
    challenge = store.get(captcha_id)
    if not challenge:
        return False, "CAPTCHA challenge not found or already expired"

    expected_sig, expiry = challenge

    # 3. Check expiration
    now = time.time()
    if now > expiry:
        store.consume(captcha_id, expiry)
        return False, "CAPTCHA challenge has expired"

    # 4. Verify answer against HMAC signature using constant-time comparison
    normalized_answer = normalize_captcha_answer(user_answer)
    computed_sig = compute_challenge_signature(captcha_id, normalized_answer, int(expiry))

    if not hmac.compare_digest(expected_sig, computed_sig):
        return False, "Incorrect CAPTCHA answer"

    # 5. Consume challenge atomically (single use guaranteed)
    store.consume(captcha_id, expiry)

    return True, "OK"
