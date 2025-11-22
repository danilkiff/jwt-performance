# Create secrets and keys

This directory contains key material used by:

- Spring Cloud Gateway (Nimbus JOSE, PEM → JWK)
- k6 load tests (HS256 via `k6/crypto`, RS256/ES256 via `k6/experimental/webcrypto`)

File names below assume:

- `secrets-dev/` — on classpath for the gateway
- `secrets/` — used directly by k6 (`../secrets/...` in scripts)

Adjust paths if you diverge.

## HS256

Used by:

- Gateway `JwtFilter` as HMAC secret
- `load-hs256.js` via `open("../secrets/hs256-secret.txt")`

Generate 256-bit random secret:

```bash
openssl rand -hex 32 > hs256-secret.txt
````

> Note: k6 script trims trailing newline, gateway reads the file as raw bytes.

## RS256

Used by:

* Gateway: **public key** (`rs256-public.pem`) via Nimbus `RSAKey.parseFromPEMEncodedObjects(...)`
* k6: **PKCS#8 private key** (`rs256-private-pkcs8.pem`) via WebCrypto

### Generate RSA keypair (PKCS#1 + X.509)

```bash
openssl genrsa -out rs256-private.pem 2048
openssl rsa -in rs256-private.pem -pubout -out rs256-public.pem
```

* `rs256-public.pem` → gateway (classpath:/secrets-dev/rs256-public.pem)

### Convert private key to PKCS#8 for k6 WebCrypto

```bash
openssl pkcs8 -topk8 -nocrypt \
  -in rs256-private.pem \
  -out rs256-private-pkcs8.pem
```

* `rs256-private-pkcs8.pem` → k6 (`../secrets/rs256-private-pkcs8.pem` in `load-rs256.js`)

## ES256 (P-256)

Used by:

* Gateway: **public EC key** (`es256-public.pem`) via Nimbus `ECKey.parseFromPEMEncodedObjects(...)`
* k6: **PKCS#8 private key** (`es256-private-pkcs8.pem`) via WebCrypto

### Generate EC keypair (SEC1 + X.509)

```bash
openssl ecparam -name prime256v1 -genkey -noout -out es256-private.pem
openssl ec -in es256-private.pem -pubout -out es256-public.pem
```

* `es256-public.pem` → gateway (classpath:/secrets-dev/es256-public.pem)

### Convert EC private key to PKCS#8 for k6 WebCrypto

```bash
openssl pkcs8 -topk8 -nocrypt \
  -in es256-private.pem \
  -out es256-private-pkcs8.pem
```

* `es256-private-pkcs8.pem` → k6 (`../secrets/es256-private-pkcs8.pem` in `load-es256.js`)

## RSA for JWE (RSA-OAEP + AES-GCM)

Used by:

- Gateway: **private RSA key** (`rsa-private.pem`) for JWE decryption (`RSADecrypter(jwePrivateKey)` in `JwtFilter`)
- External JWE generator (Java/Nimbus): **public RSA key** (`rsa-public.pem`) to produce a list of valid compact JWE tokens for load tests

### Generate RSA keypair

```bash
openssl genrsa -out rsa-private.pem 2048
openssl rsa  -in rsa-private.pem -pubout -out rsa-public.pem
````

### Usage in the system

* `rsa-private.pem` placed on the gateway classpath and configured as `JWE_PRIVATE_KEY: classpath:/secrets-dev/rsa-private.pem`
* `rsa-public.pem` used only by an **external JWE token generator** (Java/Nimbus or another JOSE implementation), which produces a file with **pre-generated compact JWE tokens**

### Why no JWE generation inside k6

k6 does not implement full JOSE/JWE support. A valid compact JWE requires:

* header (JSON → base64url)
* CEK generation
* RSA-OAEP wrapping of CEK
* AES-GCM encryption (ciphertext + tag)
* assembly into `header.encryptedKey.iv.ciphertext.tag`

The load test does not measure JWE creation cost — only the **JWE parsing + RSA decryption** path inside Spring Cloud Gateway.

Therefore, for load tests: JWE tokens are generated **outside k6**, once saved to `jwe-tokens.txt` k6 picks a random token per request.

This keeps the test consistent with the RS256/ES256 setups: gateway validates/decrypts; k6 only drives load.