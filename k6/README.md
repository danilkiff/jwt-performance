# k6 Load Test Suite

Synthetic load tests for evaluating JWT/JWE verification overhead in Spring Cloud Gateway.  
All tokens are **pre-generated** to remove signing cost from the benchmark and isolate gateway crypto paths.

## Structure

```text
k6/
  load-hs256.js   # HMAC-SHA256 JWT
  load-rs256.js   # RSA RS256 JWT
  load-es256.js   # ECDSA ES256 JWT
  load-jwe.js     # JWE (RSA-OAEP + A256GCM)

output/
  hs256-tokens.txt
  rs256-tokens.txt
  es256-tokens.txt
  jwe-tokens.txt
```

Each script picks a random token from the corresponding `output/*.txt` file and issues a simple `GET /api/ping` with
header `Authorization: Bearer <token>`.

Gateway does the heavy lifting:

- HS256 (`MACVerifier`);
- RS256/ES256 (`SignedJWT.verify()`);
- JWE (`JWEObject.parse() + RSADecrypter`).

## Running tests

From the `k6/` directory:

```bash
k6 run load-hs256.js
k6 run load-rs256.js
k6 run load-es256.js
k6 run load-jwe.js
```

Each script defaults to:

```javascript
export const options = {
  vus: 200,
  duration: "60s",
};
```

Adjust VUs and duration to push the gateway to steady-state throughput.

## Token generation

Tokens in `output/` are produced by the Python tool:

```
python tools/generate_all.py -n 10000
```

This ensures:

- consistent payload shape;
- uniform randomness (avoids hot-path optimization);
- identical benchmarking conditions across algorithms.

## Purpose

The suite measures:

- raw verification cost of HS256 / RS256 / ES256;
- JWE parsing + RSA-OAEP unwrap + AES-GCM decrypt;
- header parsing overhead under load;
- overall request-level throughput impact on Spring Cloud Gateway.

No application logic, no database, no business flow — only crypto paths and routing.
This keeps the benchmark stable, reproducible, and architecture-level meaningful.

