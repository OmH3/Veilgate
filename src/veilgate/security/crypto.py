"""Cryptographic operations, key derivation, and token generation for Veilgate Vault."""

import base64
import os
from pathlib import Path

import keyring
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from veilgate.config.constants import CROCKFORD_BASE32_ALPHABET
from veilgate.exceptions.types import VaultCryptoError
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.security.crypto")

FALLBACK_KEY_DIR: Path = Path(os.environ.get("LOCALAPPDATA", "~/.veilgate")).expanduser() / "veilgate"
FALLBACK_KEY_FILE: Path = FALLBACK_KEY_DIR / "master.key"


def resolve_master_key(configured_key_b64: str | None = None) -> bytes:
    """Resolve 32-byte master key from config, OS keyring, or persistent fallback file.

    Args:
        configured_key_b64: Optional base64-encoded key from settings/env.

    Returns:
        32-byte raw cryptographic key.

    Raises:
        VaultCryptoError: If key decoding or provisioning fails.
    """
    if configured_key_b64:
        try:
            key = base64.b64decode(configured_key_b64)
            if len(key) != 32:
                raise VaultCryptoError(f"VEILGATE_MASTER_KEY must be exactly 32 bytes (got {len(key)})")
            return key
        except Exception as e:
            raise VaultCryptoError(f"Failed to decode VEILGATE_MASTER_KEY: {e}") from e

    # Check OS keyring
    try:
        stored = keyring.get_password("veilgate", "master_key")
        if stored:
            key = base64.b64decode(stored)
            if len(key) == 32:
                return key
    except Exception:
        # Keyring may not be available on headless/CI systems; proceed to filesystem fallback
        pass

    # Check filesystem fallback
    try:
        if FALLBACK_KEY_FILE.exists():
            key_b64 = FALLBACK_KEY_FILE.read_text(encoding="utf-8").strip()
            key = base64.b64decode(key_b64)
            if len(key) == 32:
                return key
    except Exception as e:
        logger.warning(f"Failed to read fallback key file {FALLBACK_KEY_FILE}: {e}")

    # Generate new 32-byte random key and persist
    new_key = os.urandom(32)
    new_key_b64 = base64.b64encode(new_key).decode("utf-8")

    try:
        keyring.set_password("veilgate", "master_key", new_key_b64)
    except Exception:
        pass

    try:
        FALLBACK_KEY_DIR.mkdir(parents=True, exist_ok=True)
        FALLBACK_KEY_FILE.write_text(new_key_b64, encoding="utf-8")
        logger.info(f"SUCCESS | Generated new master key and saved to {FALLBACK_KEY_FILE}")
    except Exception as e:
        logger.warning(f"Could not persist fallback master key to {FALLBACK_KEY_FILE}: {e}")

    return new_key


class VaultCrypto:
    """AES-256-GCM encryption and HMAC-SHA256 indexing operations."""

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise VaultCryptoError(f"Master key must be 32 bytes (got {len(master_key)})")

        # Derive separate AES and HMAC keys using HKDF-SHA256
        self._enc_key: bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"veilgate_vault_enc_v1",
        ).derive(master_key)

        self._mac_key: bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"veilgate_vault_mac_v1",
        ).derive(master_key)

        self._aesgcm: AESGCM = AESGCM(self._enc_key)

    def encrypt(self, plaintext: str) -> tuple[bytes, bytes]:
        """Encrypt plaintext with AES-256-GCM.

        Args:
            plaintext: Raw sensitive string.

        Returns:
            Tuple of (ciphertext_with_auth_tag, 12_byte_nonce).

        Raises:
            VaultCryptoError: If encryption fails.
        """
        try:
            nonce = os.urandom(12)
            data = plaintext.encode("utf-8")
            ciphertext = self._aesgcm.encrypt(nonce, data, None)
            return ciphertext, nonce
        except Exception as e:
            raise VaultCryptoError(f"Encryption failed: {e}") from e

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> str:
        """Decrypt ciphertext with AES-256-GCM.

        Args:
            ciphertext: Encrypted bytes with auth tag.
            nonce: 12-byte initialization vector.

        Returns:
            Decrypted plaintext string.

        Raises:
            VaultCryptoError: If decryption or authentication tag verification fails.
        """
        try:
            decrypted = self._aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted.decode("utf-8")
        except Exception as e:
            raise VaultCryptoError(f"Decryption failed: {e}") from e

    def compute_hmac(self, value: str) -> bytes:
        """Compute HMAC-SHA256 for deterministic token indexing without leaking plaintext.

        Args:
            value: Plaintext value to hash.

        Returns:
            32-byte HMAC digest.
        """
        h = hmac.HMAC(self._mac_key, hashes.SHA256())
        h.update(value.strip().lower().encode("utf-8"))
        return h.finalize()


def generate_crockford_token_id() -> str:
    """Generate a random 6-character Crockford Base32 token ID.

    Returns:
        6-character Crockford Base32 identifier (e.g. '7K3QF2').
    """
    # 5 random bytes = 40 bits = 8 base32 characters, take first 6
    random_bytes = os.urandom(5)
    num = int.from_bytes(random_bytes, byteorder="big")
    chars: list[str] = []
    for _ in range(6):
        num, remainder = divmod(num, 32)
        chars.append(CROCKFORD_BASE32_ALPHABET[remainder])
    return "".join(reversed(chars))
