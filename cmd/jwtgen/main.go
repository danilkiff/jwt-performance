package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	var (
		countFlag = flag.Int("count", 1000, "Number of tokens per algorithm")
		nFlag     = flag.Int("n", 0, "Alias for --count")

		noHS256 = flag.Bool("no-hs256", false, "Skip HS256 tokens")
		noRS256 = flag.Bool("no-rs256", false, "Skip RS256 tokens")
		noES256 = flag.Bool("no-es256", false, "Skip ES256 tokens")
		noJWE   = flag.Bool("no-jwe", false, "Skip JWE tokens")
	)

	flag.Parse()

	count := *countFlag
	if *nFlag > 0 {
		count = *nFlag
	}
	if count <= 0 {
		log.Fatalf("count must be > 0, got %d", count)
	}

	repoRoot, err := os.Getwd()
	if err != nil {
		log.Fatalf("getwd: %v", err)
	}
	secretsDir := filepath.Join(repoRoot, "secrets")
	outputDir := filepath.Join(repoRoot, "output")

	fmt.Printf("Repo root: %s\n", repoRoot)
	fmt.Printf("Secrets:   %s\n", secretsDir)
	fmt.Printf("Output:    %s\n", outputDir)
	fmt.Printf("Count:     %d per algorithm\n", count)

	// HS256
	if !*noHS256 {
		secretText, err := loadText(filepath.Join(secretsDir, "hs256-secret.txt"))
		if err != nil {
			log.Fatalf("HS256 secret: %v", err)
		}
		gen := newHS256Generator([]byte(secretText))
		outPath := filepath.Join(outputDir, "hs256-tokens.txt")
		if err := generateTokensToFile(outPath, count, gen); err != nil {
			log.Fatalf("generate HS256 tokens: %v", err)
		}
		fmt.Printf("HS256   -> %s (%d tokens)\n", outPath, count)
	}

	// RS256
	if !*noRS256 {
		privPath := filepath.Join(secretsDir, "rs256-private.pem")
		gen, err := newRS256Generator(privPath)
		if err != nil {
			log.Fatalf("RS256 generator: %v", err)
		}
		outPath := filepath.Join(outputDir, "rs256-tokens.txt")
		if err := generateTokensToFile(outPath, count, gen); err != nil {
			log.Fatalf("generate RS256 tokens: %v", err)
		}
		fmt.Printf("RS256   -> %s (%d tokens)\n", outPath, count)
	}

	// ES256
	if !*noES256 {
		privPath := filepath.Join(secretsDir, "es256-private.pem")
		gen, err := newES256Generator(privPath)
		if err != nil {
			log.Fatalf("ES256 generator: %v", err)
		}
		outPath := filepath.Join(outputDir, "es256-tokens.txt")
		if err := generateTokensToFile(outPath, count, gen); err != nil {
			log.Fatalf("generate ES256 tokens: %v", err)
		}
		fmt.Printf("ES256   -> %s (%d tokens)\n", outPath, count)
	}

	// JWE
	if !*noJWE {
		pubPath := filepath.Join(secretsDir, "rsa-public.pem")
		gen, err := newJWEGenerator(pubPath)
		if err != nil {
			log.Fatalf("JWE generator: %v", err)
		}
		outPath := filepath.Join(outputDir, "jwe-tokens.txt")
		if err := generateTokensToFile(outPath, count, gen); err != nil {
			log.Fatalf("generate JWE tokens: %v", err)
		}
		fmt.Printf("JWE     -> %s (%d tokens)\n", outPath, count)
	}

	fmt.Println("Done.")
}

