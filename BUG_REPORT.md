# Bug: SQLCipher VFS fails to create new encrypted databases

## Summary

The SQLCipher VFS implementation can successfully read existing encrypted databases, but fails when attempting to create a new encrypted database. The error returned is `file is not a database (26)` (SQLITE_NOTADB).

## Environment

- Package: `modernc.org/sqlite`
- Commit: `d83cfcd` (Add SQLCipher VFS support)
- Go version: (run `go version` to fill in)
- OS: Linux (WSL2)

## Reproduction

```go
package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

func main() {
	// Remove any existing test file
	os.Remove("/tmp/test_new_encrypted.db")

	// Try to create a new encrypted database
	dsn := "/tmp/test_new_encrypted.db?_sqlcipher_key=mysecretkey"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		fmt.Println("Open error:", err)
		os.Exit(1)
	}
	defer db.Close()

	// This fails with "file is not a database (26)"
	if err := db.Ping(); err != nil {
		fmt.Println("Ping error:", err)
		os.Exit(1)
	}

	fmt.Println("Success!")
}
```

**Expected behavior:** A new encrypted database file is created successfully.

**Actual behavior:** `Ping()` (or any query) fails with error `file is not a database (26)`.

## Root Cause Analysis

The issue appears to be in `sqlcipher_vfs.go` in the `sqlcipherReadRange` function (around line 362-405).

When SQLite opens a new (empty) database file, it attempts to read the header to determine if it's a valid database. The VFS intercepts this read and:

1. Calls `ensureKeys()` which correctly generates a new salt for an empty file (lines 479-493)
2. Attempts to read from the underlying file via `sqlcipherCallRead()` (line 374)
3. When the read returns `SQLITE_IOERR_SHORT_READ` (empty file), it returns zeroed data (lines 375-387)
4. However, if the read "succeeds" with an empty or partial buffer, it proceeds to call `decryptPage()` (line 392)
5. `decryptPage()` fails because there's no valid encrypted data to decrypt
6. The function returns `SQLITE_NOTADB` (line 394)

The issue is that for a brand new file, there are no pages to decrypt - the VFS should recognize this case and return empty/zeroed pages rather than attempting decryption.

### Relevant code path:

```go
// sqlcipher_vfs.go, sqlcipherReadRange()
func sqlcipherReadRange(tls *libc.TLS, state *sqlcipherFileState, buf []byte, offset int64) int32 {
    // ...
    rc := sqlcipherCallRead(tls, state.baseFile, pageBuf, pageOffset)
    if rc == sqlite3.SQLITE_IOERR_SHORT_READ {
        // This branch handles empty pages correctly
        // ...
        continue
    }
    if rc != sqlite3.SQLITE_OK {
        return rc
    }
    // BUG: For a new file, we reach here but pageBuf contains no valid encrypted data
    plain, err := state.decryptPage(int(page+1), pageBuf)
    if err != nil {
        return sqlite3.SQLITE_NOTADB  // <-- Error occurs here
    }
    // ...
}
```

## Suggested Fix

The VFS should check if the file is empty/new before attempting to decrypt pages. Possible approaches:

1. Track whether the file was newly created and skip decryption for reads before the first write
2. Check if the page contains all zeros (indicating uninitialized) before attempting decryption
3. Handle the case where `sqlcipherCallRead` returns OK but the file size is 0

## Workaround

Currently, the only workaround is to use an existing encrypted database or create databases without encryption.

## Test Case

A test case has been added to demonstrate this bug:

**File:** `sqlcipher_test.go`

**Run with:**
```bash
go test -v -run TestSQLCipher
```

**Results:**
```
=== RUN   TestSQLCipherCreateNewDatabase
    sqlcipher_test.go:27: Failed to ping new encrypted database: file is not a database (26)
--- FAIL: TestSQLCipherCreateNewDatabase (0.18s)
=== RUN   TestSQLCipherReadExistingDatabase
    sqlcipher_test.go:124: Successfully read encrypted database with 374 objects
--- PASS: TestSQLCipherReadExistingDatabase (0.21s)
```

- `TestSQLCipherCreateNewDatabase` - Fails, demonstrating the bug
- `TestSQLCipherReadExistingDatabase` - Passes, confirming reading existing encrypted DBs works

## Notes

- Reading existing encrypted databases works correctly
- Tested with both `_sqlcipher_key` (passphrase) and `_sqlcipher_key_hex` (raw key)
- Tested with and without `_sqlcipher_hmac=false`
