package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	jose "github.com/dvsekhvalnov/jose2go"
	Rsa "github.com/dvsekhvalnov/jose2go/keys/rsa"
	ecc "github.com/dvsekhvalnov/jose2go/keys/ecc"
)

type Claims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Rnd string `json:"rnd"`
}

// псевдослучайный генератор (как в Python random), с фиксированным seed
// для воспроизводимости; блокируем для безопасного доступа из горутин.
var (
	rng   = rand.New(rand.NewSource(13666))
	rngMu sync.Mutex
)

const randLen = 16

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func randString(n int) string {
	rngMu.Lock()
	defer rngMu.Unlock()

	b := make([]rune, n)
	for i := 0; i < n; i++ {
		b[i] = letters[rng.Intn(len(letters))]
	}
	return string(b)
}

func baseClaims() Claims {
	now := time.Now().Unix()
	return Claims{
		Sub: randString(randLen),
		Iat: now,
		Rnd: randString(randLen),
	}
}

func loadText(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ----- Генераторы токенов (функции, пригодные для тестирования) -----

func newHS256Generator(secret []byte) func() (string, error) {
	return func() (string, error) {
		claims := baseClaims()
		payload, err := json.Marshal(claims)
		if err != nil {
			return "", err
		}
		token, err := jose.Sign(string(payload), jose.HS256, secret)
		if err != nil {
			return "", err
		}
		return token, nil
	}
}

func newRS256Generator(privateKeyPath string) (func() (string, error), error) {
	pemBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	privKey, err := Rsa.ReadPrivate(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("read RS256 private key: %w", err)
	}

	return func() (string, error) {
		claims := baseClaims()
		payload, err := json.Marshal(claims)
		if err != nil {
			return "", err
		}
		token, err := jose.Sign(string(payload), jose.RS256, privKey)
		if err != nil {
			return "", err
		}
		return token, nil
	}, nil
}

func newES256Generator(privateKeyPath string) (func() (string, error), error) {
	pemBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	privKey, err := ecc.ReadPrivate(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("read ES256 private key: %w", err)
	}

	return func() (string, error) {
		claims := baseClaims()
		payload, err := json.Marshal(claims)
		if err != nil {
			return "", err
		}
		token, err := jose.Sign(string(payload), jose.ES256, privKey)
		if err != nil {
			return "", err
		}
		return token, nil
	}, nil
}

func newJWEGenerator(publicKeyPath string) (func() (string, error), error) {
	pemBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}
	pubKey, err := Rsa.ReadPublic(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("read RSA public key for JWE: %w", err)
	}

	return func() (string, error) {
		claims := baseClaims()
		payload, err := json.Marshal(claims)
		if err != nil {
			return "", err
		}
		// RSA-OAEP + A256GCM, как в Python-скрипте
		token, err := jose.Encrypt(string(payload), jose.RSA_OAEP, jose.A256GCM, pubKey)
		if err != nil {
			return "", err
		}
		return token, nil
	}, nil
}

// ----- Параллельная генерация, использующая все ядра -----

// generateTokens параллельно генерирует count токенов, используя все CPU.
func generateTokens(count int, genFn func() (string, error)) ([]string, error) {
	if count <= 0 {
		return []string{}, nil
	}

	workers := runtime.NumCPU()
	if workers > count {
		workers = count
	}

	tokens := make([]string, count)
	var wg sync.WaitGroup

	var firstErr error
	var errOnce sync.Once

	base := count / workers
	rem := count % workers

	start := 0
	for i := 0; i < workers; i++ {
		n := base
		if i < rem {
			n++
		}
		s := start
		e := s + n
		start = e

		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			for idx := s; idx < e; idx++ {
				tok, err := genFn()
				if err != nil {
					errOnce.Do(func() { firstErr = err })
					return
				}
				tokens[idx] = tok
			}
		}(s, e)
	}

	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return tokens, nil
}

// generateTokensToFile генерирует токены и пишет их в файл по одному в строке.
func generateTokensToFile(path string, count int, genFn func() (string, error)) error {
	tokens, err := generateTokens(count, genFn)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, tok := range tokens {
		if _, err := w.WriteString(tok); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	}
	return w.Flush()
}

// ----- Утилиты для тестов -----

func decodeJWTPayload(token string) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, fmt.Errorf("expected 3 parts in JWT, got %d", len(parts))
	}
	dec := base64.RawURLEncoding
	payloadBytes, err := dec.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(payloadBytes, &c); err != nil {
		return c, err
	}
	return c, nil
}

func isJWECompact(token string) bool {
	// JWE compact serialization: 5 компонентов через '.'
	return len(strings.Split(token, ".")) == 5
}

