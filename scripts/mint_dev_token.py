"""Mint JWTs for local development and manual testing. Never use in production.

    python -m scripts.mint_dev_token --client-id demo-app
    python -m scripts.mint_dev_token --client-id admin --roles governance_admin

On first use a throwaway RSA key pair is created under `data/dev-keys/`. Point the API at the
public key with `CS_JWT_PUBLIC_KEY_PATH=data/dev-keys/public.pem`.
"""

import argparse
import time
import uuid
from collections.abc import Sequence
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import Settings
from app.core.roles import Role

DEFAULT_KEY_DIR = Path("data/dev-keys")
PRIVATE_KEY_NAME = "private.pem"
PUBLIC_KEY_NAME = "public.pem"
KEY_ID = "dev-key-1"


def ensure_keypair(directory: Path) -> tuple[Path, Path]:
    """Create the key pair if it does not exist and return (private_path, public_path)."""
    private_path = directory / PRIVATE_KEY_NAME
    public_path = directory / PUBLIC_KEY_NAME
    if private_path.exists() and public_path.exists():
        return private_path, public_path
    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    private_path.chmod(0o600)
    return private_path, public_path


def mint_token(
    private_key_path: Path,
    *,
    client_id: str,
    roles: Sequence[Role],
    ttl_seconds: int,
    issuer: str,
    audience: str,
) -> str:
    now = int(time.time())
    claims: dict[str, object] = {
        "iss": issuer,
        "aud": audience,
        "sub": f"sub-{client_id}",
        "client_id": client_id,
        "roles": [role.value for role in roles],
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(
        claims,
        private_key_path.read_bytes(),
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )


def main(argv: Sequence[str] | None = None) -> int:
    settings = Settings()
    parser = argparse.ArgumentParser(description="Mint a development JWT.")
    parser.add_argument("--client-id", required=True)
    parser.add_argument(
        "--roles",
        nargs="*",
        default=[],
        choices=[role.value for role in Role],
        help="Token roles. Service callers need none; their access comes from registration.",
    )
    parser.add_argument("--ttl", type=int, default=3600, help="Lifetime in seconds.")
    parser.add_argument("--key-dir", type=Path, default=DEFAULT_KEY_DIR)
    args = parser.parse_args(argv)

    private_path, public_path = ensure_keypair(args.key_dir)
    token = mint_token(
        private_path,
        client_id=args.client_id,
        roles=[Role(r) for r in args.roles],
        ttl_seconds=args.ttl,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
    )
    print(token)
    print(f"# verify with CS_JWT_PUBLIC_KEY_PATH={public_path.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
