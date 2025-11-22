# Create secret and keys

## HS256

```bash
openssl rand -hex 32 > hs256-secret.txt
```

## RS256

```bash
openssl genrsa -out rs256-private.pem 2048
openssl rsa -in rs256-private.pem -pubout -out rs256-public.pem
```

## ES256 (P-256)

```bash
openssl ecparam -name prime256v1 -genkey -noout -out es256-private.pem
openssl ec -in es256-private.pem -pubout -out es256-public.pem
```

### RSA for JWE (RSA-OAEP + AES-GCM)

```bash
openssl genrsa -out rsa-private.pem 2048
openssl rsa -in rsa-private.pem -pubout -out rsa-public.pem
```