# JWT/JWE Spring Cloud Gateway Performance Bench

A reproducible benchmark suite for measuring **signature-verification** and **JWE-decryption** cost inside **Spring Cloud Gateway 2025.x** (Java 21, Nimbus JOSE).  
Each request carries a **unique token** to avoid hot-path inlining and show real event-loop crypto overhead.

## Logical flowchart

```mermaid
flowchart

    subgraph SUT["System Under Test"]
        GW["gateway"]
        BE["backend"]
    end

    subgraph Crypto["Crypto"]
        TG["tools/generate-all.py <br> (Python token generator)"]
        SECRETS["secrets/         <br> (private keys, secrets)"]
    end

    OUTPUT["output/*.txt      <br> (pre-generated JWT/JWE)"]
    K6["k6 load scripts       <br> (load-*.js, warmup.js)"]
    RESULTS["results/run-*/   <br> (k6 JSON summaries)"]
    
    subgraph DS["Data Analysis"]
        NB["Jupyter notebook"]
    end
    
    SECRETS --> TG 
    TG --> OUTPUT

    OUTPUT --> K6
    K6 -->|HTTP load| GW

    GW -->|/api/ping| BE
    GW -->|/plain/api/ping| BE

    K6 -->|--summary-export| RESULTS
    RESULTS --> NB
```

## How it works

Gateway classifies tokens on the fly:

- **HS256 / RS256 / ES256** → `SignedJWT.parse` → `MACVerifier` / `RSASSAVerifier` / `ECDSAVerifier`
- **JWE** → `JWEObject.parse` → `RSADecrypter` (RSA-OAEP + AES-GCM)

Backend is intentionally trivial. The only measurable components are:

- Nimbus parsing & crypto;
- SCG routing;
- Netty event-loop saturation under pressure.

Token uniqueness removes JVM inline-caching and signature-reuse artifacts.

## Running the full benchmark

The `run.sh` script automates the end-to-end workflow: handles environment validation, dependency setup, 
token generation, container startup, readiness checks, and sequential execution of all k6 workloads.

See the script source for the exact sequence of operations.

## Manual execution (optional)

- generate keys as described in [`secrets/README.md`](secrets/README.md);
- generate JWT/JWE as described in [`tools/README.md`](tools/README.md);
- run docker-compose and start k6 tests:

```bash
docker compose up -d --build

k6 run k6/warmup.js
k6 run k6/load-hs256.js
k6 run k6/load-rs256.js
k6 run k6/load-es256.js
k6 run k6/load-jwe.js
```

## What the bench reveals

- throughput changes across HS256 → RS256 → ES256 → JWE;
- latency behavior per algorithm;
- pressure on the Netty/SCG event loop;
- impact of raw cryptography with routing, without any application logic.

See [analysis.ipynb](results/analysis.ipynb) for the full analysis.

## License

This work is licensed under **CC BY-SA-4.0**. See [`LICENSE.md`](LICENSE.md) for attribution requirements.
