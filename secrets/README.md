# Secrets and keys

## TL;DR

| Algorithm | Gateway uses | Python uses | k6 uses          |
| --------- | ------------ | ----------- | ---------------- |
| HS256     | secret bytes | secret      | preloaded tokens |
| RS256     | public key   | private key | preloaded tokens |
| ES256     | public key   | private key | preloaded tokens |
| JWE       | private key  | public key  | preloaded tokens |

## Details 

Key material for:

- Spring Cloud Gateway (Nimbus JOSE, PEM → JWK)
- Python token generator (`tools/generate-all.py`)
- k6 load tests (preloaded compact tokens from `output/*.txt`)

Two separate locations:

- `secrets-dev/` — mounted into the gateway (classpath)
- `secrets/` — used by Python and k6

Names below assume this layout.

## HS256

- Gateway: HMAC secret (raw bytes from file)
- Python generator: `generate_hs256(secret)`
- k6: reads pre-generated tokens from `output/hs256-tokens.txt`

Generate a 256-bit secret:

```bash
openssl rand -hex 32 > hs256-secret.txt
````

Note: the gateway reads raw bytes; Python trims newlines automatically.

## RS256

- Gateway verifies with **public key**.
- Python generator signs with **private key** (PKCS#1).
- k6 uses **pre-generated tokens** (no WebCrypto required anymore).

### Generate RSA keypair (PKCS#1 private + X.509 public)

```bash
openssl genrsa -out rs256-private.pem 2048
openssl rsa -in rs256-private.pem -pubout -out rs256-public.pem
```

Files:

* `rs256-public.pem` → `secrets-dev/` → Gateway (`RS256_PUBLIC_KEY`)
* `rs256-private.pem` → `secrets/` → Python generator

## ES256 (P-256)

- Gateway verifies with **public EC key**.
- Python generator signs with **private key**.
- k6 uses only pre-generated tokens.

### Generate EC keypair (SEC1 private + X.509 public)

```bash
openssl ecparam -name prime256v1 -genkey -noout -out es256-private.pem
openssl ec -in es256-private.pem -pubout -out es256-public.pem
```

Files:

* `es256-public.pem` → `secrets-dev/` → Gateway (`ES256_PUBLIC_KEY`)
* `es256-private.pem` → `secrets/` → Python generator

## RSA for JWE (RSA-OAEP + AES-GCM)

- Gateway decrypts using **private key**.
- Python generator encrypts using **public key**.
- k6 uses pre-generated compact JWE tokens.

### Generate RSA keypair

```bash
openssl genrsa -out rsa-private.pem 2048
openssl rsa  -in rsa-private.pem -pubout -out rsa-public.pem
```

Files:

* `rsa-private.pem`  → `secrets-dev/` → Gateway (`JWE_PRIVATE_KEY`)
* `rsa-public.pem`   → `secrets/` → Python generator

### Why JWE is not created in k6

k6 does not support JOSE/JWE. A valid compact JWE requires:

- JOSE header → base64url
- CEK generation
- RSA-OAEP encryption of CEK
- AES-GCM encryption of payload
- Assembling `header.encryptedKey.iv.ciphertext.tag`

The load test measures gateway JWE parsing + RSA decryption, not JWE creation. Therefore, JWE tokens are generated once
by Python and stored in `output/jwe-tokens.txt`; k6 only reads and replays them.