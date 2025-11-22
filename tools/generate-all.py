#!/usr/bin/env python3

"""
Generate JWT/JWE tokens for load testing.

- HS256  -> output/hs256-tokens.txt
- RS256  -> output/rs256-tokens.txt
- ES256  -> output/es256-tokens.txt
- JWE    -> output/jwe-tokens.txt
"""

import argparse
import time
import random
import string
import json
from pathlib import Path

from jose import jwt, jwe
from tqdm.auto import tqdm  # прогрессбар

REPO_ROOT = Path(__file__).resolve().parents[1]
SECRETS_DIR = REPO_ROOT / "secrets"
OUTPUT_DIR = REPO_ROOT / "output"


def rand_str(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def base_claims() -> dict:
    now = int(time.time())
    return {
        "sub": rand_str(16),
        "iat": now,
        "rnd": rand_str(16),
    }


def load_text(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(path)
    return path.read_text(encoding="utf-8").strip()


def generate_hs256(secret: str) -> str:
    claims = base_claims()
    return jwt.encode(claims, secret, algorithm="HS256")


def generate_rs256(private_pem: str) -> str:
    claims = base_claims()
    return jwt.encode(claims, private_pem, algorithm="RS256")


def generate_es256(private_pem: str) -> str:
    claims = base_claims()
    return jwt.encode(claims, private_pem, algorithm="ES256")


def generate_jwe(public_pem: str) -> str:
    payload = base_claims()
    return jwe.encrypt(
        json.dumps(payload),
        public_pem,
        algorithm="RSA-OAEP",
        encryption="A256GCM",
    ).decode("utf-8")


def generate_to_file(path: Path, count: int, desc: str, gen_fn, *gen_args) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for _ in tqdm(range(count), desc=desc):
            token = gen_fn(*gen_args)
            f.write(token)
            f.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate JWT/JWE tokens for load testing."
    )
    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=1000,
        help="Number of tokens per algorithm (default: 10000)",
    )
    parser.add_argument(
        "--no-hs256", action="store_true", help="Skip HS256 tokens"
    )
    parser.add_argument(
        "--no-rs256", action="store_true", help="Skip RS256 tokens"
    )
    parser.add_argument(
        "--no-es256", action="store_true", help="Skip ES256 tokens"
    )
    parser.add_argument(
        "--no-jwe", action="store_true", help="Skip JWE tokens"
    )

    args = parser.parse_args()
    n = args.count

    print(f"Repo root: {REPO_ROOT}")
    print(f"Secrets:   {SECRETS_DIR}")
    print(f"Output:    {OUTPUT_DIR}")
    print(f"Count:     {n} per algorithm")

    # HS256
    if not args.no_hs256:
        secret = load_text(SECRETS_DIR / "hs256-secret.txt")
        out = OUTPUT_DIR / "hs256-tokens.txt"
        generate_to_file(out, n, "HS256", generate_hs256, secret)
        print(f"HS256   -> {out} ({n} tokens)")

    # RS256
    if not args.no_rs256:
        rs_priv = load_text(SECRETS_DIR / "rs256-private.pem")
        out = OUTPUT_DIR / "rs256-tokens.txt"
        generate_to_file(out, n, "RS256", generate_rs256, rs_priv)
        print(f"RS256   -> {out} ({n} tokens)")

    # ES256
    if not args.no_es256:
        es_priv = load_text(SECRETS_DIR / "es256-private.pem")
        out = OUTPUT_DIR / "es256-tokens.txt"
        generate_to_file(out, n, "ES256", generate_es256, es_priv)
        print(f"ES256   -> {out} ({n} tokens)")

    # JWE
    if not args.no_jwe:
        rsa_pub = load_text(SECRETS_DIR / "rsa-public.pem")
        out = OUTPUT_DIR / "jwe-tokens.txt"
        generate_to_file(out, n, "JWE", generate_jwe, rsa_pub)
        print(f"JWE     -> {out} ({n} tokens)")

    print("Done.")


if __name__ == "__main__":
    random.seed(13666)
    main()
