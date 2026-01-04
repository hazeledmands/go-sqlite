// Copyright 2025 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite // import "modernc.org/sqlite"

import (
	"crypto/hmac"
	"hash"
)

func sqlcipherDeriveKeys(cfg *sqlcipherConfig, salt []byte) ([]byte, []byte) {
	var encKey []byte

	if cfg.keyIsRaw {
		// Raw key mode: use the key directly as encryption key
		encKey = make([]byte, 32)
		copy(encKey, cfg.key)
	} else {
		// Passphrase mode: derive encryption key using PBKDF2
		encKey = pbkdf2Key(cfg.key, salt, cfg.kdfIter, 32, cfg.hmacHash())
	}

	var hmacKey []byte
	if cfg.hmac {
		// Create masked salt for HMAC key derivation.
		// XOR each byte with the mask to ensure the HMAC key derivation
		// uses a different salt than the encryption key derivation.
		hmacSalt := make([]byte, len(salt))
		for i := range salt {
			hmacSalt[i] = salt[i] ^ sqlcipherHMACSaltMask
		}
		// Derive HMAC key using the encryption key as the PBKDF2 password.
		// HMAC key length is always 32 bytes (same as encryption key), not the hash output size.
		// This matches real SQLCipher behavior (KEYLENGTH_SQLCIPHER = 32).
		hmacKey = pbkdf2Key(encKey, hmacSalt, cfg.fastKDFIter, 32, cfg.hmacHash())
	}

	return encKey, hmacKey
}

func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	if keyLen == 0 {
		return nil
	}
	prf := func(key, data []byte) []byte {
		mac := hmac.New(h, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
	hashLen := h().Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	var blockBuf [4]byte
	for block := 1; block <= numBlocks; block++ {
		blockBuf[0] = byte(block >> 24)
		blockBuf[1] = byte(block >> 16)
		blockBuf[2] = byte(block >> 8)
		blockBuf[3] = byte(block)
		data := make([]byte, 0, len(salt)+4)
		data = append(data, salt...)
		data = append(data, blockBuf[:]...)
		u := prf(password, data)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			u = prf(password, u)
			for x := range t {
				t[x] ^= u[x]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}
