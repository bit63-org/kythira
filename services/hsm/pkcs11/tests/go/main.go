// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// crypto11-smoke drives libkythira_pkcs11.so from Go's
// github.com/ThalesGroup/crypto11 (.kiro/specs/virtual-hsm/ task 10b,
// requirement 5.6): an ECDSA key generated on the token signs as a
// crypto.Signer and verifies with crypto/ecdsa, the key is found again by
// label, and an AES key on the token seals and opens with GCM.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"

	"github.com/ThalesGroup/crypto11"
)

func main() {
	module := flag.String("module", "", "the PKCS#11 library")
	token := flag.String("token", "", "the token label")
	pin := flag.String("pin", "", "the user PIN")
	flag.Parse()
	if err := run(*module, *token, *pin); err != nil {
		fmt.Fprintln(os.Stderr, "crypto11-smoke:", err)
		os.Exit(1)
	}
	fmt.Println("crypto11-smoke: ok")
}

func run(module, token, pin string) error {
	ctx, err := crypto11.Configure(&crypto11.Config{Path: module, TokenLabel: token, Pin: pin})
	if err != nil {
		return fmt.Errorf("configure: %w", err)
	}
	defer ctx.Close()

	signer, err := ctx.GenerateECDSAKeyPairWithLabel([]byte("go-ec-id"), []byte("go-ec"), elliptic.P256())
	if err != nil {
		return fmt.Errorf("generate ECDSA: %w", err)
	}
	digest := sha256.Sum256([]byte("signed from go"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is %T", signer.Public())
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("signature does not verify")
	}
	found, err := ctx.FindKeyPair(nil, []byte("go-ec"))
	if err != nil || found == nil {
		return fmt.Errorf("find key pair by label: %v", err)
	}
	if !found.Public().(*ecdsa.PublicKey).Equal(pub) {
		return fmt.Errorf("found a different key")
	}

	key, err := ctx.GenerateSecretKeyWithLabel([]byte("go-aes-id"), []byte("go-aes"), 256, crypto11.CipherAES)
	if err != nil {
		return fmt.Errorf("generate AES: %w", err)
	}
	gcm, err := key.NewGCM()
	if err != nil {
		return fmt.Errorf("GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	plain := []byte("sealed from go")
	sealed := gcm.Seal(nil, nonce, plain, []byte("aad"))
	opened, err := gcm.Open(nil, nonce, sealed, []byte("aad"))
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if !bytes.Equal(opened, plain) {
		return fmt.Errorf("GCM round trip differs")
	}
	sealed[0] ^= 1
	if _, err := gcm.Open(nil, nonce, sealed, []byte("aad")); err == nil {
		return fmt.Errorf("GCM opened tampered bytes")
	}
	return nil
}
