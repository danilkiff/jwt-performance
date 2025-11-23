# JWT/JWE generator

Python helper for pre-generating JWT/JWE tokens used by k6 load tests.

## What this does

`generate-all.py` creates compact tokens for all four algorithms and writes them to `output/`:

- `hs256-tokens.txt`   – HS256 JWT
- `rs256-tokens.txt`   – RS256 JWT
- `es256-tokens.txt`   – ES256 JWT
- `jwe-tokens.txt`     – JWE (RSA-OAEP + A256GCM)

k6 scripts then only read tokens and hit the gateway. Signing cost is outside the benchmark.

## Requirements

Use virtual env **from repo root**:

```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

Expected input:

```text
secrets/
  hs256-secret.txt
  rs256-private.pem
  es256-private.pem
  rsa-public.pem
```

Secrets are created according to [secrets/README.md](../secrets/README.md)

## Usage

```bash
python generate-all.py
```

Key options:

```bash
# set token count per algorithm (default: 1000)
python tools/generate-all.py -n 10000

# generate only JWE tokens
python tools/generate-all.py --no-hs256 --no-rs256 --no-es256

# generate only HS256 + RS256
python tools/generate-all.py --no-es256 --no-jwe
```

Each run overwrites the corresponding `output/*-tokens.txt`.

## Implementation details

* HS256 / RS256 / ES256: `python-jose` (`jwt.encode(...)`) with standard JOSE compact serialization.
* JWE: `python-jose` `jwe.encrypt(...)` with `RSA-OAEP` + `A256GCM`.
* Claims are minimal and random: `sub`, `iat`, `rnd`.
* RNG is seeded (`random.seed(13666)`) for reproducible token sets across runs.
