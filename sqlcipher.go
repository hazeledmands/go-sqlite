// Copyright 2025 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite // import "modernc.org/sqlite"

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unsafe"

	"modernc.org/libc"
	sqlite3 "modernc.org/sqlite/lib"
)

const (
	sqlcipherDefaultKDFIter     = 256000
	sqlcipherDefaultFastKDFIter = 2
	sqlcipherDefaultPageSize    = 4096
	sqlcipherDefaultHMAC        = true
	sqlcipherDefaultHMACAlg     = "sha512"
	// sqlcipherSaltSize is 16 bytes as used by SQLCipher.
	sqlcipherSaltSize = 16
)

type sqlcipherConfig struct {
	key             []byte
	keyIsRaw        bool
	kdfIter         int
	fastKDFIter     int
	pageSize        int
	hmac            bool
	hmacAlgorithm   string
	plaintextHeader int
}

func (c *sqlcipherConfig) validate() error {
	if len(c.key) == 0 {
		return errors.New("sqlcipher key is required")
	}
	if c.kdfIter <= 0 {
		return fmt.Errorf("sqlcipher kdf_iter must be positive")
	}
	if c.fastKDFIter <= 0 {
		return fmt.Errorf("sqlcipher fast_kdf_iter must be positive")
	}
	if c.pageSize <= 0 || c.pageSize%16 != 0 {
		return fmt.Errorf("sqlcipher page_size must be a positive multiple of 16")
	}
	if c.plaintextHeader != 0 {
		return fmt.Errorf("sqlcipher plaintext_header_size is not supported in this build")
	}
	if c.hmacAlgorithm != "sha256" && c.hmacAlgorithm != "sha512" {
		return fmt.Errorf("sqlcipher hmac_algorithm must be sha256 or sha512")
	}
	return nil
}

func parseSQLCipherConfig(query string) (*sqlcipherConfig, error) {
	if query == "" {
		return nil, nil
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return nil, err
	}
	key := strings.TrimSpace(q.Get("_sqlcipher_key"))
	keyHex := strings.TrimSpace(q.Get("_sqlcipher_key_hex"))
	if key == "" && keyHex == "" {
		return nil, nil
	}
	if key != "" && keyHex != "" {
		return nil, fmt.Errorf("sqlcipher key and key_hex are mutually exclusive")
	}
	cfg := &sqlcipherConfig{
		kdfIter:         sqlcipherDefaultKDFIter,
		fastKDFIter:     sqlcipherDefaultFastKDFIter,
		pageSize:        sqlcipherDefaultPageSize,
		hmac:            sqlcipherDefaultHMAC,
		hmacAlgorithm:   sqlcipherDefaultHMACAlg,
		plaintextHeader: 0,
	}
	if key != "" {
		cfg.key = []byte(key)
	} else {
		decoded, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, fmt.Errorf("sqlcipher key_hex must be hex: %w", err)
		}
		cfg.key = decoded
		cfg.keyIsRaw = true
	}
	if v := strings.TrimSpace(q.Get("_sqlcipher_kdf_iter")); v != "" {
		kdfIter, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("sqlcipher kdf_iter must be an integer")
		}
		cfg.kdfIter = kdfIter
	}
	if v := strings.TrimSpace(q.Get("_sqlcipher_fast_kdf_iter")); v != "" {
		fastIter, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("sqlcipher fast_kdf_iter must be an integer")
		}
		cfg.fastKDFIter = fastIter
	}
	if v := strings.TrimSpace(q.Get("_sqlcipher_page_size")); v != "" {
		pageSize, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("sqlcipher page_size must be an integer")
		}
		cfg.pageSize = pageSize
	}
	if v := strings.TrimSpace(q.Get("_sqlcipher_hmac")); v != "" {
		on, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("sqlcipher hmac must be a bool")
		}
		cfg.hmac = on
	}
	if v := strings.TrimSpace(q.Get("_sqlcipher_hmac_algorithm")); v != "" {
		cfg.hmacAlgorithm = strings.ToLower(v)
	}
	if v := strings.TrimSpace(q.Get("_sqlcipher_plaintext_header_size")); v != "" {
		plain, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("sqlcipher plaintext_header_size must be an integer")
		}
		cfg.plaintextHeader = plain
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *sqlcipherConfig) signature() string {
	if c == nil {
		return ""
	}
	key := c.key
	if c.keyIsRaw {
		key = append([]byte("raw:"), key...)
	}
	material := fmt.Sprintf("%x:%d:%d:%d:%t:%s:%d", key, c.kdfIter, c.fastKDFIter, c.pageSize, c.hmac, c.hmacAlgorithm, c.plaintextHeader)
	h := sha256.Sum256([]byte(material))
	return hex.EncodeToString(h[:])
}

func (c *sqlcipherConfig) hmacHash() func() hash.Hash {
	if c.hmacAlgorithm == "sha256" {
		return sha256.New
	}
	return sha512.New
}

func (c *sqlcipherConfig) hmacSize() int {
	if c.hmacAlgorithm == "sha256" {
		return sha256.Size
	}
	return sha512.Size
}

func configureSQLCipher(c *conn, cfg *sqlcipherConfig) error {
	if cfg == nil {
		return nil
	}
	reserved := 16
	if cfg.hmac {
		reserved += cfg.hmacSize()
	}
	dbName, err := libc.CString("main")
	if err != nil {
		return err
	}
	rc := sqlite3.Xsqlite3_file_control(c.tls, c.db, dbName, sqlite3.SQLITE_FCNTL_RESERVE_BYTES, uintptr(unsafe.Pointer(&reserved)))
	libc.Xfree(c.tls, dbName)
	if rc != sqlite3.SQLITE_OK {
		return fmt.Errorf("sqlcipher reserve bytes setup failed: %d", rc)
	}
	pageCount, err := queryInt(c, "pragma page_count")
	if err != nil {
		return err
	}
	if pageCount == 0 {
		if _, err := c.exec(context.Background(), fmt.Sprintf("pragma page_size=%d", cfg.pageSize), nil); err != nil {
			return err
		}
	}
	if _, err := c.exec(context.Background(), fmt.Sprintf("pragma reserved_size=%d", reserved), nil); err != nil {
		return err
	}
	return nil
}

func queryInt(c *conn, query string) (int, error) {
	rows, err := c.query(context.Background(), query, nil)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	cols := rows.Columns()
	if len(cols) == 0 {
		return 0, errors.New("no columns returned")
	}
	values := make([]driver.Value, len(cols))
	if err := rows.Next(values); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, errors.New("no rows returned")
		}
		return 0, err
	}
	switch v := values[0].(type) {
	case int64:
		return int(v), nil
	case int:
		return v, nil
	case []byte:
		i, err := strconv.Atoi(string(v))
		if err != nil {
			return 0, err
		}
		return i, nil
	case string:
		i, err := strconv.Atoi(v)
		if err != nil {
			return 0, err
		}
		return i, nil
	default:
		return 0, fmt.Errorf("unexpected type %T", v)
	}
}
