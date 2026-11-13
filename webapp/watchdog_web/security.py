"""Password, cifratura delle credenziali, token.

- Password degli utenti: scrypt (libreria standard), con sale casuale, confronto a tempo costante.
- Credenziali SSH degli obiettivi: cifrate con Fernet (AES + HMAC); la chiave deriva da
  WATCHDOG_SECRET_KEY, quindi una copia del solo database non basta a leggerle.
- Token dell'API: mostrati una volta sola, nel database c'è solo lo SHA-256.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}
MIN_PASSWORD_LENGTH = 12
TOKEN_PREFIX = "wd_"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=32, **_SCRYPT)
    return "scrypt${n}${r}${p}${salt}${digest}".format(
        salt=base64.b64encode(salt).decode(), digest=base64.b64encode(digest).decode(), **_SCRYPT)


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        got = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), dklen=len(expected),
                             n=int(n), r=int(r), p=int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


# Hash di una password casuale: quando l'utente non esiste si verifica contro questo, così
# la risposta impiega lo stesso tempo e non rivela quali nomi utente esistono.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_problem(password: str, username: str = "") -> str | None:
    """Perché la password non va bene (None se va bene)."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"La password deve avere almeno {MIN_PASSWORD_LENGTH} caratteri."
    if len(password) > 200:
        return "La password è troppo lunga (massimo 200 caratteri)."
    if username and username.lower() in password.lower():
        return "La password non deve contenere il nome utente."
    if len(set(password)) < 6:
        return "La password è troppo ripetitiva."
    lowered = password.lower()
    if any(word in lowered for word in _OBVIOUS):
        return "La password contiene una parola troppo facile da indovinare (per esempio «password» o «watchdog»)."
    return None


# Parole che rendono una password facile da indovinare anche se lunga.
_OBVIOUS = ("password", "passw0rd", "watchdog", "qwerty", "123456", "abcdef", "admin", "laboratorio")


class SecretBox:
    """Cifra e decifra le credenziali degli obiettivi."""

    def __init__(self, secret_key: str) -> None:
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"watchdog-web",
                   info=b"target-credentials").derive(secret_key.encode("utf-8"))
        self._fernet = Fernet(base64.urlsafe_b64encode(key))

    def encrypt(self, plain: str) -> str:
        return self._fernet.encrypt(plain.encode("utf-8")).decode("ascii") if plain else ""

    def decrypt(self, token: str) -> str:
        """Solleva ValueError se il dato non si decifra (chiave cambiata o dato alterato)."""
        if not token:
            return ""
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError) as e:
            raise ValueError("credenziale non decifrabile: WATCHDOG_SECRET_KEY è cambiata?") from e


def new_api_token() -> tuple[str, str, str]:
    """(token da mostrare una volta, prefisso per l'elenco, hash da salvare)."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, token[:10], hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_csrf_token() -> str:
    return secrets.token_urlsafe(24)


# --------------------------------------------------------------------------- verifica in due passaggi
# Codici a tempo (TOTP, RFC 6238): 6 cifre, cambiano ogni 30 secondi. Funzionano con
# Google Authenticator, Microsoft Authenticator, Aegis, FreeOTP, 1Password e simili.

TOTP_PERIOD = 30
TOTP_DIGITS = 6


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_step(at: float | None = None) -> int:
    return int((time.time() if at is None else at) // TOTP_PERIOD)


def totp_code(secret: str, step: int, digits: int = TOTP_DIGITS, digest=hashlib.sha1) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), digest).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def totp_match(secret: str, code: str, last_step: int, at: float | None = None) -> int | None:
    """Passo temporale del codice se è valido e non già usato (None altrimenti).

    Accetta il codice del periodo corrente e di quello prima e dopo (orologi un po' sfasati).
    Un codice già usato non vale una seconda volta: chi lo vede alle spalle non può riusarlo.
    """
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != TOTP_DIGITS:
        return None
    now = totp_step(at)
    for step in (now - 1, now, now + 1):
        if step > last_step and hmac.compare_digest(totp_code(secret, step), code):
            return step
    return None


def totp_uri(secret: str, username: str, issuer: str = "WatchDog") -> str:
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&period={TOTP_PERIOD}&digits={TOTP_DIGITS}"


def totp_qr_data_uri(uri: str) -> str:
    """QR code come immagine SVG in un data: URI (nessuna risorsa esterna, compatibile con la CSP)."""
    import segno
    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#16233f", light="#ffffff")
