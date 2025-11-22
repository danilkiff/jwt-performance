# JWT/JWE Gateway Performance Bench

## Purpose

Benchmark the verification cost of HS256, RS256, ES256, and JWE inside Spring Cloud Gateway (Java 21).
Each request carries a **unique token** to eliminate JVM hot-path effects and expose real crypto overhead.

## Structure

```text
gateway/      Spring Cloud Gateway + unified verifier (Nimbus JOSE)
backend/      Minimal REST target (/api/ping)
k6/           Load scripts for each algorithm
secrets/      HS256, RS256, ES256 key material; RSA keypair for JWE (RSA-OAEP + AES-GCM)
docker-compose.yml
```

## How it works

Gateway detects token type:

* **JWT (HS256/RS256/ES256)** → signature verify
* **JWE** → RSA decrypt (+ optional nested JWS)

Backend is intentionally trivial so the only measurable cost is crypto + SCG routing.

## Running

Generate keys (HS256/RS256/ES256/JWE) as described [here](secrets/README.md), then:

```bash
docker-compose up --build
cd k6
k6 run load-hs256.js
k6 run load-rs256.js
k6 run load-es256.js
k6 run load-jwe.js
```

k6 scripts generate *per-request* tokens to avoid false results from caching or signature reuse.

## What you measure

* steady-state RPS impact per algorithm
* SCG event-loop saturation points
* latency distribution across HS256 → RS256 → ES256 → JWE
* effect of token size (thin/fat JWT, encrypted blob)

## Scope boundaries

Not included: database latency, user-directory lookups, cross-DC traffic, advanced routing filters, or cache warming.
The bench isolates pure token processing.

## License

Licensed under [CC BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/), see [LICENSE.md](LICENSE.md).
