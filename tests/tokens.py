"""Mints JWTs signed with a throwaway RSA key, for tests and local development."""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://idp.example.internal"
AUDIENCE = "central-security"


@dataclass
class KeyPair:
    kid: str = "test-key-1"
    private_key: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )

    @property
    def public_pem(self) -> str:
        return (
            self.private_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

    def jwks(self) -> dict[str, Any]:  # Any: JWK documents are heterogeneous JSON.
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key(), as_dict=True)
        return {"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]}

    def mint(
        self,
        *,
        client_id: str = "app-1",
        subject: str | None = None,
        roles: list[str] | str | None = None,
        expires_in: int = 300,
        issuer: str = ISSUER,
        audience: str = AUDIENCE,
        kid: str | None = "default",
        algorithm: str = "RS256",
        drop: tuple[str, ...] = (),
        extra: dict[str, Any] | None = None,  # Any: arbitrary extra claims.
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "sub": subject if subject is not None else f"sub-{client_id}",
            "client_id": client_id,
            "iat": now,
            "exp": now + expires_in,
            "jti": str(uuid.uuid4()),
        }
        if roles is not None:
            claims["roles"] = roles
        claims.update(extra or {})
        for name in drop:
            claims.pop(name, None)
        headers = {} if kid is None else {"kid": self.kid if kid == "default" else kid}
        return jwt.encode(claims, self.private_key, algorithm=algorithm, headers=headers)
