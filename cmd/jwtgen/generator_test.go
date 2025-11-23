package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	jose "github.com/dvsekhvalnov/jose2go"
)

// ---------- утилиты ----------

func writeRSAPrivateKeyPEM(t *testing.T, dir, name string) (string, *rsa.PrivateKey) {
	t.Helper()

	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	der := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile RSA private: %v", err)
	}
	return path, priv
}

func writeRSAPublicKeyPEM(t *testing.T, dir, name string, pub *rsa.PublicKey) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile RSA public: %v", err)
	}
	return path
}

func writeECPrivateKeyPEM(t *testing.T, dir, name string) string {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile EC private: %v", err)
	}
	return path
}

// ---------- существующие тесты немного доработаны ----------

func TestRandStringLength(t *testing.T) {
	s := randString(16)
	if len(s) != 16 {
		t.Fatalf("expected length 16, got %d", len(s))
	}
}

func TestHS256GeneratorProducesValidJWT(t *testing.T) {
	secret := []byte("test-secret")
	gen := newHS256Generator(secret)

	token, err := gen()
	if err != nil {
		t.Fatalf("gen error: %v", err)
	}

	claims, err := decodeJWTPayload(token)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	if len(claims.Sub) != randLen {
		t.Fatalf("unexpected sub length: %d", len(claims.Sub))
	}
	if len(claims.Rnd) != randLen {
		t.Fatalf("unexpected rnd length: %d", len(claims.Rnd))
	}
	if claims.Iat == 0 {
		t.Fatalf("iat must be non-zero")
	}
}

func TestGenerateTokensUsesAllCount(t *testing.T) {
	var calls int64

	gen := func() (string, error) {
		atomic.AddInt64(&calls, 1)
		return "tok", nil
	}

	const count = 1000
	tokens, err := generateTokens(count, gen)
	if err != nil {
		t.Fatalf("generateTokens error: %v", err)
	}
	if len(tokens) != count {
		t.Fatalf("expected %d tokens, got %d", count, len(tokens))
	}
	if calls != count {
		t.Fatalf("expected %d gen calls, got %d", count, calls)
	}
}

func TestGenerateTokensErrorPropagates(t *testing.T) {
	var calls int64
	gen := func() (string, error) {
		if atomic.AddInt64(&calls, 1) > 5 {
			return "", os.ErrInvalid
		}
		return "tok", nil
	}

	_, err := generateTokens(20, gen)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestGenerateTokensToFileWritesLines(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "tokens.txt")

	gen := func() (string, error) {
		return "tok", nil
	}

	const count = 123
	if err := generateTokensToFile(outPath, count, gen); err != nil {
		t.Fatalf("generateTokensToFile error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != count {
		t.Fatalf("expected %d lines, got %d", count, len(lines))
	}
}

func TestGenerateTokensToFileZeroCount(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "zero.txt")

	gen := func() (string, error) {
		t.Fatalf("generator must not be called for count=0")
		return "", nil
	}

	if err := generateTokensToFile(outPath, 0, gen); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(strings.TrimSpace(string(data))) != 0 {
		t.Fatalf("expected empty file for zero count")
	}
}

// ---------- новые тесты на I/O и ключи ----------

func TestLoadTextTrimAndMissing(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "secret.txt")

	if err := os.WriteFile(path, []byte("  hello\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	text, err := loadText(path)
	if err != nil {
		t.Fatalf("loadText error: %v", err)
	}
	if text != "hello" {
		t.Fatalf("expected 'hello', got %q", text)
	}

	_, err = loadText(filepath.Join(tmpDir, "missing.txt"))
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestNewRS256GeneratorAndTokenRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	privPath, privKey := writeRSAPrivateKeyPEM(t, tmpDir, "rs256-private.pem")

	genFn, err := newRS256Generator(privPath)
	if err != nil {
		t.Fatalf("newRS256Generator: %v", err)
	}

	token, err := genFn()
	if err != nil {
		t.Fatalf("genFn: %v", err)
	}

	// проверяем, что jose.Decode умеет декодировать наш токен тем же ключом
	payload, headers, err := jose.Decode(token, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("jose.Decode: %v", err)
	}
	if headers["alg"] != "RS256" {
		t.Fatalf("expected alg=RS256, got %v", headers["alg"])
	}

	var c Claims
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if c.Sub == "" || c.Rnd == "" || c.Iat == 0 {
		t.Fatalf("claims not populated: %+v", c)
	}
}

func TestNewES256GeneratorProducesJWT(t *testing.T) {
	tmpDir := t.TempDir()
	privPath := writeECPrivateKeyPEM(t, tmpDir, "es256-private.pem")

	genFn, err := newES256Generator(privPath)
	if err != nil {
		t.Fatalf("newES256Generator: %v", err)
	}

	token, err := genFn()
	if err != nil {
		t.Fatalf("genFn: %v", err)
	}

	// ES256 тоже даёт стандартный JWT из трёх частей
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in ES256 JWT, got %d", len(parts))
	}

	claims, err := decodeJWTPayload(token)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}
	if claims.Sub == "" || claims.Rnd == "" || claims.Iat == 0 {
		t.Fatalf("claims not populated: %+v", claims)
	}
}

func TestNewJWEGeneratorAndDecrypt(t *testing.T) {
	tmpDir := t.TempDir()
	privPath, privKey := writeRSAPrivateKeyPEM(t, tmpDir, "jwe-private.pem")
	_ = privPath // не нужен, но оставим для симметрии

	pubPath := writeRSAPublicKeyPEM(t, tmpDir, "rsa-public.pem", &privKey.PublicKey)

	genFn, err := newJWEGenerator(pubPath)
	if err != nil {
		t.Fatalf("newJWEGenerator: %v", err)
	}

	token, err := genFn()
	if err != nil {
		t.Fatalf("genFn: %v", err)
	}
	if !isJWECompact(token) {
		t.Fatalf("expected compact JWE (5 parts), got %q", token)
	}

	// расшифровываем тем же приватным ключом
	payload, headers, err := jose.Decode(token, privKey)
	if err != nil {
		t.Fatalf("jose.Decode JWE: %v", err)
	}
	if headers["alg"] != "RSA-OAEP" {
		t.Fatalf("expected alg=RSA-OAEP, got %v", headers["alg"])
	}
	if headers["enc"] != "A256GCM" {
		t.Fatalf("expected enc=A256GCM, got %v", headers["enc"])
	}

	var c Claims
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("unmarshal JWE payload: %v", err)
	}
	if c.Sub == "" || c.Rnd == "" || c.Iat == 0 {
		t.Fatalf("claims not populated: %+v", c)
	}
}

// ---------- негативные кейсы для decodeJWTPayload ----------

func TestDecodeJWTPayloadInvalidParts(t *testing.T) {
	_, err := decodeJWTPayload("only.two")
	if err == nil {
		t.Fatalf("expected error for invalid parts count")
	}
}

func TestDecodeJWTPayloadInvalidBase64(t *testing.T) {
	// 3 части, но payload не base64url
	_, err := decodeJWTPayload("a.!@#.c")
	if err == nil {
		t.Fatalf("expected error for invalid base64 payload")
	}
}

func TestIsJWECompact(t *testing.T) {
	if !isJWECompact("a.b.c.d.e") {
		t.Fatalf("expected true for 5 parts")
	}
	if isJWECompact("a.b.c") {
		t.Fatalf("expected false for 3 parts")
	}
}

func TestNewRS256Generator_FileNotFound(t *testing.T) {
	_, err := newRS256Generator(filepath.Join(t.TempDir(), "missing.pem"))
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestNewRS256Generator_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.pem")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := newRS256Generator(path)
	if err == nil {
		t.Fatalf("expected error for invalid PEM")
	}
}

func TestNewES256Generator_FileNotFound(t *testing.T) {
	_, err := newES256Generator(filepath.Join(t.TempDir(), "missing-ec.pem"))
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestNewES256Generator_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad-es.pem")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := newES256Generator(path)
	if err == nil {
		t.Fatalf("expected error for invalid PEM")
	}
}

func TestNewJWEGenerator_FileNotFound(t *testing.T) {
	_, err := newJWEGenerator(filepath.Join(t.TempDir(), "missing-pub.pem"))
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestNewJWEGenerator_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad-pub.pem")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := newJWEGenerator(path)
	if err == nil {
		t.Fatalf("expected error for invalid PEM")
	}
}

