package sqlite

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// growStack consumes about depth*256 bytes of goroutine stack and returns, so
// the goroutine is left with a large, mostly unused stack that the GC will
// shrink (copy to a new address) at its next opportunity.
//
//go:noinline
func growStack(depth int) {
	var pad [256]byte
	pad[depth%256] = byte(depth)
	if depth > 0 {
		growStack(depth - 1)
	}
	_ = pad[0]
}

func sqlcipherGCWorkload(dbPath string) error {
	// Cheap KDF: the bug under test is unrelated to key derivation.
	db, err := sql.Open("sqlite", dbPath+"?_sqlcipher_key=k&_sqlcipher_kdf_iter=2")
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	// Re-grow the stack before every statement so the GC has a shrinkable
	// stack to move while that statement is inside libc.
	growStack(1000)
	if _, err := db.Exec("CREATE TABLE a (id INTEGER PRIMARY KEY, v TEXT); CREATE TABLE b (id INTEGER PRIMARY KEY, v TEXT)"); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	for i := 0; i < 20; i++ {
		growStack(1000)
		if _, err := db.Exec("INSERT INTO a (v) VALUES (?)", fmt.Sprint(i)); err != nil {
			return fmt.Errorf("insert %d: %w", i, err)
		}
	}
	var n int
	growStack(1000)
	if err := db.QueryRow("SELECT count(*) FROM a").Scan(&n); err != nil {
		return fmt.Errorf("count: %w", err)
	}
	if n != 20 {
		return fmt.Errorf("count: got %d want 20", n)
	}
	return nil
}

// TestSQLCipherSurvivesGCStackMoves is the regression test for djtool-bha: the
// SQLCipher VFS used to hand libc addresses of Go memory, so a GC stack shrink
// or collection during a libc call corrupted pages ("file is not a database").
// Before the fix this failed in every run (5-15 of 960 workloads).
func TestSQLCipherSurvivesGCStackMoves(t *testing.T) {
	if testing.Short() {
		t.Skip("GC stress test")
	}
	dir := t.TempDir()
	stop := make(chan struct{})
	gcDone := make(chan struct{})
	go func() {
		defer close(gcDone)
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	}()

	const workers, perWorker = 8, 40
	errs := make(chan error, workers*perWorker)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				errs <- sqlcipherGCWorkload(filepath.Join(dir, fmt.Sprintf("w%d_%03d.db", w, i)))
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	<-gcDone
	close(errs)

	failures := 0
	for err := range errs {
		if err != nil {
			failures++
			if failures <= 5 {
				t.Errorf("workload: %v", err)
			}
		}
	}
	if failures > 0 {
		t.Fatalf("%d/%d workloads failed under GC pressure", failures, workers*perWorker)
	}
}

// TestSQLCipherUnreadableSaltIsNotRewritten checks that an existing file whose
// salt cannot be read fails to open and is left byte-for-byte unchanged. (The
// VFS used to invent a new salt and write it over the file header, which
// destroys a real database.)
func TestSQLCipherUnreadableSaltIsNotRewritten(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "short.db")
	original := []byte("12345678") // non-empty but shorter than the 16-byte salt
	if err := os.WriteFile(dbPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_sqlcipher_key=k&_sqlcipher_kdf_iter=2")
	if err != nil {
		t.Fatal(err)
	}
	_, queryErr := db.Exec("CREATE TABLE t (x)")
	db.Close()
	if queryErr == nil {
		t.Fatal("expected an error for a file whose salt cannot be read, got nil")
	}

	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("file was modified: before %q, after %q", original, after)
	}
}
