## Token generation

Tokens in `output/` are produced by the [jwt-token-generator](https://github.com/danilkiff/jwt-token-generator) 
tool. Examples:

```bash
# HS256
jwt-claims -count=${TOKENS_COUNT} | \
  jwt-sign-hs256 --key-file "${secrets}/hs256-secret.txt" \
  > "${output}/hs256-tokens.txt"

# RS256
jwt-claims -count=${TOKENS_COUNT} | \
  jwt-sign-rs256 --key-file "${secrets}/rs256-private.pem" \
  > "${output}/rs256-tokens.txt"

# ES256
jwt-claims -count=${TOKENS_COUNT} | \
  jwt-sign-es256 --key-file "${secrets}/es256-private.pem" \
  > "${output}/es256-tokens.txt"

# JWE
jwt-claims -count=${TOKENS_COUNT} | \
  jwe-encrypt-rsa-oaep-a256gcm --pub-key-file "${secrets}/rsa-public.pem" \
  > "${output}/jwe-tokens.txt"
```
