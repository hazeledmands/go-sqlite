// Copyright 2025 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestSQLCipherCreateNewDatabase(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_encrypted.db")

	dsn := dbPath + "?_sqlcipher_key=testpassword"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// This currently fails with "file is not a database (26)"
	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping new encrypted database: %v", err)
	}

	// Create a table
	_, err = db.Exec("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Insert data
	_, err = db.Exec("INSERT INTO test (name) VALUES (?)", "alice")
	if err != nil {
		t.Fatalf("Failed to insert data: %v", err)
	}

	// Read it back
	var name string
	err = db.QueryRow("SELECT name FROM test WHERE id = 1").Scan(&name)
	if err != nil {
		t.Fatalf("Failed to read data: %v", err)
	}
	if name != "alice" {
		t.Fatalf("Expected 'alice', got '%s'", name)
	}

	db.Close()

	// Reopen and verify persistence
	db2, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("Failed to reopen database: %v", err)
	}
	defer db2.Close()

	err = db2.QueryRow("SELECT name FROM test WHERE id = 1").Scan(&name)
	if err != nil {
		t.Fatalf("Failed to read data after reopen: %v", err)
	}
	if name != "alice" {
		t.Fatalf("Expected 'alice' after reopen, got '%s'", name)
	}
}

func TestSQLCipherReadExistingDatabase(t *testing.T) {
	// This test requires an existing encrypted database
	// Skip if the test database doesn't exist
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("Cannot get home directory")
	}

	configPath := filepath.Join(home, ".djtool.toml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Skip("Test config file ~/.djtool.toml not found")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Skip("Cannot read config file")
	}

	// Simple parsing
	var dbkey, dbpath string
	for _, line := range splitLines(string(data)) {
		line = trimSpace(line)
		if hasPrefix(line, "dbkey") {
			dbkey = extractTestValue(line)
		} else if hasPrefix(line, "dbpath") {
			dbpath = extractTestValue(line)
		}
	}

	if dbkey == "" || dbpath == "" {
		t.Skip("Config file missing dbkey or dbpath")
	}

	if _, err := os.Stat(dbpath); os.IsNotExist(err) {
		t.Skip("Database file not found: " + dbpath)
	}

	dsn := dbpath + "?_sqlcipher_key=" + dbkey + "&_sqlcipher_hmac=false"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query sqlite_master: %v", err)
	}

	if count == 0 {
		t.Fatal("Expected non-zero count from sqlite_master")
	}

	t.Logf("Successfully read encrypted database with %d objects", count)
}

// Helper functions to avoid importing strings package in test
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func extractTestValue(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == '=' {
			val := trimSpace(line[i+1:])
			if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
				return val[1 : len(val)-1]
			}
			return val
		}
	}
	return ""
}
