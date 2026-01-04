// Copyright 2025 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite // import "modernc.org/sqlite"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"modernc.org/libc"
	sqlite3 "modernc.org/sqlite/lib"
)

type sqlcipherVFS struct {
	name   string
	cname  uintptr
	vfsPtr uintptr
	state  *sqlcipherVFSState
}

type sqlcipherVFSState struct {
	baseVFS uintptr
	config  *sqlcipherConfig
}

type sqlcipherFile struct {
	base        sqlite3.Tsqlite3_file
	vfsHandle   uintptr
	stateHandle uintptr
}

type sqlcipherFileState struct {
	mu          sync.Mutex
	config      *sqlcipherConfig
	baseFile    uintptr
	pageSize    int
	reserved    int
	salt        [sqlcipherSaltSize]byte
	hasSalt     bool
	encKey      []byte
	hmacKey     []byte
	useHMAC     bool
	hmacSize    int
	plainHeader int
}

var (
	sqlcipherVFSMu       sync.Mutex
	sqlcipherVFSRegistry = map[string]*sqlcipherVFS{}
	sqlcipherToken       uintptr
	sqlcipherObjects     = map[uintptr]interface{}{}
	sqlcipherObjectsMu   sync.Mutex
)

func sqlcipherTokenNext() uintptr { return atomic.AddUintptr(&sqlcipherToken, 1) }

func sqlcipherAddObject(o interface{}) uintptr {
	t := sqlcipherTokenNext()
	sqlcipherObjectsMu.Lock()
	sqlcipherObjects[t] = o
	sqlcipherObjectsMu.Unlock()
	return t
}

func sqlcipherGetObject(t uintptr) interface{} {
	sqlcipherObjectsMu.Lock()
	o := sqlcipherObjects[t]
	sqlcipherObjectsMu.Unlock()
	if o == nil {
		panic("internal error")
	}
	return o
}

func sqlcipherRemoveObject(t uintptr) {
	sqlcipherObjectsMu.Lock()
	delete(sqlcipherObjects, t)
	sqlcipherObjectsMu.Unlock()
}

func sqlcipherRegisterVFS(cfg *sqlcipherConfig) (string, error) {
	sig := cfg.signature()
	sqlcipherVFSMu.Lock()
	defer sqlcipherVFSMu.Unlock()
	if vfs := sqlcipherVFSRegistry[sig]; vfs != nil {
		return vfs.name, nil
	}
	tls := libc.NewTLS()
	base := sqlite3.Xsqlite3_vfs_find(tls, 0)
	if base == 0 {
		tls.Close()
		return "", errors.New("sqlite3_vfs_find returned nil")
	}
	name := fmt.Sprintf("sqlcipher_%s", sig)
	cname, err := libc.CString(name)
	if err != nil {
		tls.Close()
		return "", err
	}
	state := &sqlcipherVFSState{
		baseVFS: base,
		config:  cfg,
	}
	stateHandle := sqlcipherAddObject(state)
	vfsPtr := libc.Xmalloc(tls, libc.Tsize_t(unsafe.Sizeof(sqlite3.Tsqlite3_vfs{})))
	if vfsPtr == 0 {
		sqlcipherRemoveObject(stateHandle)
		libc.Xfree(tls, cname)
		tls.Close()
		return "", errors.New("out of memory")
	}
	baseVfs := (*sqlite3.Tsqlite3_vfs)(unsafe.Pointer(base))
	fileSize := int32(unsafe.Sizeof(sqlcipherFile{})) + baseVfs.FszOsFile
	*(*sqlite3.Tsqlite3_vfs)(unsafe.Pointer(vfsPtr)) = sqlite3.Tsqlite3_vfs{
		FiVersion:   baseVfs.FiVersion,
		FszOsFile:   fileSize,
		FmxPathname: baseVfs.FmxPathname,
		FzName:      cname,
		FpAppData:   stateHandle,
		FxOpen: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, uintptr, uintptr, int32, uintptr) int32
		}{sqlcipherOpen})),
		FxDelete:           baseVfs.FxDelete,
		FxAccess:           baseVfs.FxAccess,
		FxFullPathname:     baseVfs.FxFullPathname,
		FxDlOpen:           baseVfs.FxDlOpen,
		FxDlError:          baseVfs.FxDlError,
		FxDlSym:            baseVfs.FxDlSym,
		FxDlClose:          baseVfs.FxDlClose,
		FxRandomness:       baseVfs.FxRandomness,
		FxSleep:            baseVfs.FxSleep,
		FxCurrentTime:      baseVfs.FxCurrentTime,
		FxGetLastError:     baseVfs.FxGetLastError,
		FxCurrentTimeInt64: baseVfs.FxCurrentTimeInt64,
		FxSetSystemCall:    baseVfs.FxSetSystemCall,
		FxGetSystemCall:    baseVfs.FxGetSystemCall,
		FxNextSystemCall:   baseVfs.FxNextSystemCall,
	}
	if rc := sqlite3.Xsqlite3_vfs_register(tls, vfsPtr, 0); rc != sqlite3.SQLITE_OK {
		sqlcipherRemoveObject(stateHandle)
		libc.Xfree(tls, cname)
		libc.Xfree(tls, vfsPtr)
		tls.Close()
		return "", fmt.Errorf("sqlite3_vfs_register failed: %d", rc)
	}
	sqlcipherVFSRegistry[sig] = &sqlcipherVFS{
		name:   name,
		cname:  cname,
		vfsPtr: vfsPtr,
		state:  state,
	}
	tls.Close()
	return name, nil
}

func sqlcipherOpen(tls *libc.TLS, pVfs uintptr, zName uintptr, pFile uintptr, flags int32, pOutFlags uintptr) int32 {
	stateHandle := (*sqlite3.Tsqlite3_vfs)(unsafe.Pointer(pVfs)).FpAppData
	state := sqlcipherGetObject(stateHandle).(*sqlcipherVFSState)
	baseVfs := (*sqlite3.Tsqlite3_vfs)(unsafe.Pointer(state.baseVFS))
	pReal := uintptr(unsafe.Pointer(pFile)) + unsafe.Sizeof(sqlcipherFile{})
	*(*sqlcipherFile)(unsafe.Pointer(pFile)) = sqlcipherFile{}
	rc := (*(*func(*libc.TLS, uintptr, uintptr, uintptr, int32, uintptr) int32)(unsafe.Pointer(&struct{ uintptr }{baseVfs.FxOpen})))(tls, state.baseVFS, zName, pReal, flags, pOutFlags)
	if rc != sqlite3.SQLITE_OK {
		return rc
	}
	file := (*sqlcipherFile)(unsafe.Pointer(pFile))
	file.vfsHandle = stateHandle
	file.stateHandle = sqlcipherAddObject(newSQLCipherFileState(state.config, pReal))
	file.base.FpMethods = uintptr(unsafe.Pointer(&sqlcipherIOMethods))
	return sqlite3.SQLITE_OK
}

var sqlcipherIOMethods = sqlite3.Tsqlite3_io_methods{
	FiVersion: 2,
	FxClose: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr) int32
	}{sqlcipherClose})),
	FxRead: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, uintptr, int32, sqlite3.Sqlite3_int64) int32
	}{sqlcipherRead})),
	FxWrite: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, uintptr, int32, sqlite3.Sqlite3_int64) int32
	}{sqlcipherWrite})),
	FxTruncate: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, sqlite3.Sqlite3_int64) int32
	}{sqlcipherTruncate})),
	FxSync: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32) int32
	}{sqlcipherSync})),
	FxFileSize: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, uintptr) int32
	}{sqlcipherFileSize})),
	FxLock: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32) int32
	}{sqlcipherLock})),
	FxUnlock: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32) int32
	}{sqlcipherUnlock})),
	FxCheckReservedLock: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, uintptr) int32
	}{sqlcipherCheckReservedLock})),
	FxFileControl: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32, uintptr) int32
	}{sqlcipherFileControl})),
	FxSectorSize: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr) int32
	}{sqlcipherSectorSize})),
	FxDeviceCharacteristics: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr) int32
	}{sqlcipherDeviceCharacteristics})),
	FxShmMap: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32, int32, int32, uintptr) int32
	}{sqlcipherShmMap})),
	FxShmLock: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32, int32, int32) int32
	}{sqlcipherShmLock})),
	FxShmBarrier: *(*uintptr)(unsafe.Pointer(&struct{ f func(*libc.TLS, uintptr) }{sqlcipherShmBarrier})),
	FxShmUnmap: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32) int32
	}{sqlcipherShmUnmap})),
	FxFetch: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, sqlite3.Sqlite3_int64, int32, uintptr) int32
	}{sqlcipherFetch})),
	FxUnfetch: *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, sqlite3.Sqlite3_int64, uintptr) int32
	}{sqlcipherUnfetch})),
}

func newSQLCipherFileState(cfg *sqlcipherConfig, baseFile uintptr) *sqlcipherFileState {
	reserved := 16 // IV only
	hmacSize := 0
	if cfg.hmac {
		hmacSize = cfg.hmacSize()
		reserved += hmacSize // IV + HMAC space
		// Round to next multiple of 16 (AES block size) per SQLCipher spec
		if reserved%16 != 0 {
			reserved = (reserved/16 + 1) * 16
		}
	}
	return &sqlcipherFileState{
		config:      cfg,
		baseFile:    baseFile,
		pageSize:    cfg.pageSize,
		reserved:    reserved,
		useHMAC:     cfg.hmac,
		hmacSize:    hmacSize,
		plainHeader: cfg.plaintextHeader,
	}
}

func sqlcipherClose(tls *libc.TLS, pFile uintptr) int32 {
	file := (*sqlcipherFile)(unsafe.Pointer(pFile))
	state := sqlcipherGetObject(file.stateHandle).(*sqlcipherFileState)
	rc := sqlcipherCallClose(tls, state.baseFile)
	sqlcipherRemoveObject(file.stateHandle)
	return rc
}

func sqlcipherRead(tls *libc.TLS, pFile uintptr, zBuf uintptr, iAmt int32, iOfst sqlite3.Sqlite3_int64) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	if iAmt == 0 {
		return sqlite3.SQLITE_OK
	}
	buf := (*libc.RawMem)(unsafe.Pointer(zBuf))[:iAmt]
	if iOfst < 0 {
		return sqlite3.SQLITE_IOERR_READ
	}
	return sqlcipherReadRange(tls, state, buf, int64(iOfst))
}

func sqlcipherWrite(tls *libc.TLS, pFile uintptr, zBuf uintptr, iAmt int32, iOfst sqlite3.Sqlite3_int64) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	if iAmt == 0 {
		return sqlite3.SQLITE_OK
	}
	buf := (*libc.RawMem)(unsafe.Pointer(zBuf))[:iAmt]
	if iOfst < 0 {
		return sqlite3.SQLITE_IOERR_WRITE
	}
	return sqlcipherWriteRange(tls, state, buf, int64(iOfst))
}

func sqlcipherTruncate(tls *libc.TLS, pFile uintptr, size sqlite3.Sqlite3_int64) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallTruncate(tls, state.baseFile, size)
}

func sqlcipherSync(tls *libc.TLS, pFile uintptr, flags int32) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallSync(tls, state.baseFile, flags)
}

func sqlcipherFileSize(tls *libc.TLS, pFile uintptr, pSize uintptr) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallFileSize(tls, state.baseFile, pSize)
}

func sqlcipherLock(tls *libc.TLS, pFile uintptr, eLock int32) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallLock(tls, state.baseFile, eLock)
}

func sqlcipherUnlock(tls *libc.TLS, pFile uintptr, eLock int32) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallUnlock(tls, state.baseFile, eLock)
}

func sqlcipherCheckReservedLock(tls *libc.TLS, pFile uintptr, pRes uintptr) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallCheckReservedLock(tls, state.baseFile, pRes)
}

func sqlcipherFileControl(tls *libc.TLS, pFile uintptr, op int32, pArg uintptr) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallFileControl(tls, state.baseFile, op, pArg)
}

func sqlcipherSectorSize(tls *libc.TLS, pFile uintptr) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallSectorSize(tls, state.baseFile)
}

func sqlcipherDeviceCharacteristics(tls *libc.TLS, pFile uintptr) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallDeviceCharacteristics(tls, state.baseFile)
}

func sqlcipherShmMap(tls *libc.TLS, pFile uintptr, iPg int32, pgsz int32, flags int32, p uintptr) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallShmMap(tls, state.baseFile, iPg, pgsz, flags, p)
}

func sqlcipherShmLock(tls *libc.TLS, pFile uintptr, offset int32, n int32, flags int32) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallShmLock(tls, state.baseFile, offset, n, flags)
}

func sqlcipherShmBarrier(tls *libc.TLS, pFile uintptr) {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	sqlcipherCallShmBarrier(tls, state.baseFile)
}

func sqlcipherShmUnmap(tls *libc.TLS, pFile uintptr, deleteFlag int32) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallShmUnmap(tls, state.baseFile, deleteFlag)
}

func sqlcipherFetch(tls *libc.TLS, pFile uintptr, iOfst sqlite3.Sqlite3_int64, iAmt int32, pPtr uintptr) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallFetch(tls, state.baseFile, iOfst, iAmt, pPtr)
}

func sqlcipherUnfetch(tls *libc.TLS, pFile uintptr, iOfst sqlite3.Sqlite3_int64, pPtr uintptr) int32 {
	state := sqlcipherGetObject((*sqlcipherFile)(unsafe.Pointer(pFile)).stateHandle).(*sqlcipherFileState)
	return sqlcipherCallUnfetch(tls, state.baseFile, iOfst, pPtr)
}

func sqlcipherReadRange(tls *libc.TLS, state *sqlcipherFileState, buf []byte, offset int64) int32 {
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.ensureKeys(tls); err != nil {
		return sqlite3.SQLITE_IOERR_READ
	}
	var fileSize sqlite3.Sqlite3_int64
	if rc := sqlcipherCallFileSize(tls, state.baseFile, uintptr(unsafe.Pointer(&fileSize))); rc != sqlite3.SQLITE_OK {
		return rc
	}
	pageSize := int64(state.pageSize)
	startPage := offset / pageSize
	endPage := (offset + int64(len(buf)) - 1) / pageSize
	writePos := 0
	shortRead := offset+int64(len(buf)) > int64(fileSize)
	writeZero := func(page int64, pageOffset int64) {
		start := int64(0)
		if page == startPage {
			start = offset - pageOffset
		}
		end := pageSize
		if page == endPage {
			end = (offset + int64(len(buf))) - pageOffset
		}
		zero := make([]byte, end-start)
		copy(buf[writePos:], zero)
		writePos += int(end - start)
	}
	for page := startPage; page <= endPage; page++ {
		pageOffset := page * pageSize
		pageBuf := make([]byte, pageSize)
		if int64(fileSize) <= pageOffset {
			shortRead = true
			writeZero(page, pageOffset)
			continue
		}
		rc := sqlcipherCallRead(tls, state.baseFile, pageBuf, pageOffset)
		if rc == sqlite3.SQLITE_IOERR_SHORT_READ {
			shortRead = true
			writeZero(page, pageOffset)
			continue
		}
		if rc != sqlite3.SQLITE_OK {
			return rc
		}
		if int64(fileSize) < pageOffset+pageSize {
			shortRead = true
			writeZero(page, pageOffset)
			continue
		}
		plain, err := state.decryptPage(int(page+1), pageBuf)
		if err != nil {
			return sqlite3.SQLITE_NOTADB
		}
		start := int64(0)
		if page == startPage {
			start = offset - pageOffset
		}
		end := pageSize
		if page == endPage {
			end = (offset + int64(len(buf))) - pageOffset
		}
		copy(buf[writePos:], plain[start:end])
		writePos += int(end - start)
	}
	if shortRead {
		return sqlite3.SQLITE_IOERR_SHORT_READ
	}
	return sqlite3.SQLITE_OK
}

func sqlcipherWriteRange(tls *libc.TLS, state *sqlcipherFileState, buf []byte, offset int64) int32 {
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.ensureKeys(tls); err != nil {
		return sqlite3.SQLITE_IOERR_WRITE
	}
	var fileSize sqlite3.Sqlite3_int64
	if rc := sqlcipherCallFileSize(tls, state.baseFile, uintptr(unsafe.Pointer(&fileSize))); rc != sqlite3.SQLITE_OK {
		return rc
	}
	pageSize := int64(state.pageSize)
	startPage := offset / pageSize
	endPage := (offset + int64(len(buf)) - 1) / pageSize
	readPos := 0
	if fileSize == 0 && startPage > 0 {
		plain := make([]byte, state.pageSize)
		encrypted, err := state.encryptPage(1, plain)
		if err != nil {
			return sqlite3.SQLITE_IOERR_WRITE
		}
		rc := sqlcipherCallWrite(tls, state.baseFile, encrypted, 0)
		if rc != sqlite3.SQLITE_OK {
			return rc
		}
	}
	for page := startPage; page <= endPage; page++ {
		pageOffset := page * pageSize
		pageBuf := make([]byte, pageSize)
		rc := sqlcipherCallRead(tls, state.baseFile, pageBuf, pageOffset)
		if rc == sqlite3.SQLITE_IOERR_SHORT_READ {
			plain := make([]byte, pageSize)
			start := int64(0)
			if page == startPage {
				start = offset - pageOffset
			}
			end := pageSize
			if page == endPage {
				end = (offset + int64(len(buf))) - pageOffset
			}
			copy(plain[start:end], buf[readPos:readPos+int(end-start)])
			readPos += int(end - start)
			encrypted, err := state.encryptPage(int(page+1), plain)
			if err != nil {
				return sqlite3.SQLITE_IOERR_WRITE
			}
			rc = sqlcipherCallWrite(tls, state.baseFile, encrypted, pageOffset)
			if rc != sqlite3.SQLITE_OK {
				return rc
			}
			continue
		}
		if rc != sqlite3.SQLITE_OK {
			return rc
		}
		plain, err := state.decryptPage(int(page+1), pageBuf)
		if err != nil {
			return sqlite3.SQLITE_IOERR_WRITE
		}
		start := int64(0)
		if page == startPage {
			start = offset - pageOffset
		}
		end := pageSize
		if page == endPage {
			end = (offset + int64(len(buf))) - pageOffset
		}
		copy(plain[start:end], buf[readPos:readPos+int(end-start)])
		readPos += int(end - start)
		encrypted, err := state.encryptPage(int(page+1), plain)
		if err != nil {
			return sqlite3.SQLITE_IOERR_WRITE
		}
		rc = sqlcipherCallWrite(tls, state.baseFile, encrypted, pageOffset)
		if rc != sqlite3.SQLITE_OK {
			return rc
		}
	}
	return sqlite3.SQLITE_OK
}

func (s *sqlcipherFileState) ensureKeys(tls *libc.TLS) error {
	if s.encKey != nil {
		return nil
	}
	if !s.hasSalt {
		var fileSize sqlite3.Sqlite3_int64
		if rc := sqlcipherCallFileSize(tls, s.baseFile, uintptr(unsafe.Pointer(&fileSize))); rc != sqlite3.SQLITE_OK {
			return errors.New("file size query failed")
		}
		if fileSize == 0 {
			if _, err := rand.Read(s.salt[:]); err != nil {
				return err
			}
			s.hasSalt = true
		} else {
			buf := make([]byte, sqlcipherSaltSize)
			rc := sqlcipherCallRead(tls, s.baseFile, buf, 0)
			if rc == sqlite3.SQLITE_OK && len(buf) == sqlcipherSaltSize {
				copy(s.salt[:], buf)
				s.hasSalt = true
			} else {
				if _, err := rand.Read(s.salt[:]); err != nil {
					return err
				}
				s.hasSalt = true
				_, _ = rand.Read(buf)
				copy(buf, s.salt[:])
				_ = sqlcipherCallWrite(tls, s.baseFile, buf, 0)
			}
		}
	}
	encKey, hmacKey := sqlcipherDeriveKeys(s.config, s.salt[:])
	s.encKey = encKey
	s.hmacKey = hmacKey
	return nil
}

func (s *sqlcipherFileState) decryptPage(pageNo int, data []byte) ([]byte, error) {
	if len(data) != s.pageSize {
		return nil, errors.New("invalid page size")
	}
	plain := make([]byte, s.pageSize)
	plainHeader := s.plainHeader
	if pageNo == 1 && plainHeader == 0 {
		plainHeader = sqlcipherSaltSize
	}
	if pageNo == 1 {
		if !s.hasSalt || !sqlcipherAllZero(data[:sqlcipherSaltSize]) {
			copy(s.salt[:], data[:sqlcipherSaltSize])
			s.hasSalt = true
		}
	}
	ivOffset := s.pageSize - s.reserved
	iv := data[ivOffset : ivOffset+aes.BlockSize]
	ciphertext := data[plainHeader:ivOffset]
	if s.useHMAC {
		macStart := ivOffset + aes.BlockSize
		mac := data[macStart : macStart+s.hmacSize]
		// HMAC covers ciphertext + IV
		ciphertextWithIV := data[plainHeader : ivOffset+aes.BlockSize]
		if !s.verifyHMAC(pageNo, ciphertextWithIV, mac) {
			return nil, errors.New("hmac mismatch")
		}
	}
	block, err := aes.NewCipher(s.encKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plain[plainHeader:ivOffset], ciphertext)
	// Set SQLite header and reserved bytes AFTER decryption
	if pageNo == 1 {
		copy(plain[:plainHeader], []byte("SQLite format 3\x00")[:plainHeader])
		if len(plain) > 20 {
			plain[20] = byte(s.reserved)
		}
	}
	return plain, nil
}

func (s *sqlcipherFileState) encryptPage(pageNo int, plain []byte) ([]byte, error) {
	if len(plain) != s.pageSize {
		return nil, errors.New("invalid page size")
	}
	plainHeader := s.plainHeader
	if pageNo == 1 && plainHeader == 0 {
		plainHeader = sqlcipherSaltSize
	}
	ivOffset := s.pageSize - s.reserved
	encrypted := make([]byte, s.pageSize)
	if pageNo == 1 {
		copy(encrypted[:sqlcipherSaltSize], s.salt[:])
		if len(plain) > 20 {
			plain[20] = byte(s.reserved)
		}
	}
	iv := encrypted[ivOffset : ivOffset+aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(s.encKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted[plainHeader:ivOffset], plain[plainHeader:ivOffset])
	if s.useHMAC {
		// HMAC covers ciphertext + IV
		ciphertextWithIV := encrypted[plainHeader : ivOffset+aes.BlockSize]
		mac := s.computeHMAC(pageNo, ciphertextWithIV)
		copy(encrypted[ivOffset+aes.BlockSize:], mac)
	}
	return encrypted, nil
}

func (s *sqlcipherFileState) computeHMAC(pageNo int, ciphertextWithIV []byte) []byte {
	mac := hmac.New(s.config.hmacHash(), s.hmacKey)
	mac.Write(ciphertextWithIV)
	var pageNum [4]byte
	binary.LittleEndian.PutUint32(pageNum[:], uint32(pageNo))
	mac.Write(pageNum[:])
	return mac.Sum(nil)
}

func (s *sqlcipherFileState) verifyHMAC(pageNo int, ciphertext, expected []byte) bool {
	mac := s.computeHMAC(pageNo, ciphertext)
	return hmac.Equal(mac, expected)
}

func sqlcipherAllZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func sqlcipherCallRead(tls *libc.TLS, pFile uintptr, buf []byte, offset int64) int32 {
	if len(buf) == 0 {
		return sqlite3.SQLITE_OK
	}
	raw := (*libc.RawMem)(unsafe.Pointer(&buf[0]))[:len(buf)]
	return (*(*func(*libc.TLS, uintptr, uintptr, int32, sqlite3.Sqlite3_int64) int32)(unsafe.Pointer(&struct{ uintptr }{(*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods)).FxRead})))(tls, pFile, uintptr(unsafe.Pointer(&raw[0])), int32(len(buf)), sqlite3.Sqlite3_int64(offset))
}

func sqlcipherCallWrite(tls *libc.TLS, pFile uintptr, buf []byte, offset int64) int32 {
	if len(buf) == 0 {
		return sqlite3.SQLITE_OK
	}
	raw := (*libc.RawMem)(unsafe.Pointer(&buf[0]))[:len(buf)]
	return (*(*func(*libc.TLS, uintptr, uintptr, int32, sqlite3.Sqlite3_int64) int32)(unsafe.Pointer(&struct{ uintptr }{(*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods)).FxWrite})))(tls, pFile, uintptr(unsafe.Pointer(&raw[0])), int32(len(buf)), sqlite3.Sqlite3_int64(offset))
}

func sqlcipherCallClose(tls *libc.TLS, pFile uintptr) int32 {
	return (*(*func(*libc.TLS, uintptr) int32)(unsafe.Pointer(&struct{ uintptr }{(*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods)).FxClose})))(tls, pFile)
}

func sqlcipherCallTruncate(tls *libc.TLS, pFile uintptr, size sqlite3.Sqlite3_int64) int32 {
	return (*(*func(*libc.TLS, uintptr, sqlite3.Sqlite3_int64) int32)(unsafe.Pointer(&struct{ uintptr }{(*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods)).FxTruncate})))(tls, pFile, size)
}

func sqlcipherCallSync(tls *libc.TLS, pFile uintptr, flags int32) int32 {
	return (*(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&struct{ uintptr }{(*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods)).FxSync})))(tls, pFile, flags)
}

func sqlcipherCallFileSize(tls *libc.TLS, pFile uintptr, pSize uintptr) int32 {
	return (*(*func(*libc.TLS, uintptr, uintptr) int32)(unsafe.Pointer(&struct{ uintptr }{(*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods)).FxFileSize})))(tls, pFile, pSize)
}

func sqlcipherCallLock(tls *libc.TLS, pFile uintptr, eLock int32) int32 {
	return (*(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&struct{ uintptr }{(*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods)).FxLock})))(tls, pFile, eLock)
}

func sqlcipherCallUnlock(tls *libc.TLS, pFile uintptr, eLock int32) int32 {
	return (*(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&struct{ uintptr }{(*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods)).FxUnlock})))(tls, pFile, eLock)
}

func sqlcipherCallCheckReservedLock(tls *libc.TLS, pFile uintptr, pRes uintptr) int32 {
	return (*(*func(*libc.TLS, uintptr, uintptr) int32)(unsafe.Pointer(&struct{ uintptr }{(*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods)).FxCheckReservedLock})))(tls, pFile, pRes)
}

func sqlcipherCallFileControl(tls *libc.TLS, pFile uintptr, op int32, pArg uintptr) int32 {
	return (*(*func(*libc.TLS, uintptr, int32, uintptr) int32)(unsafe.Pointer(&struct{ uintptr }{(*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods)).FxFileControl})))(tls, pFile, op, pArg)
}

func sqlcipherCallSectorSize(tls *libc.TLS, pFile uintptr) int32 {
	return (*(*func(*libc.TLS, uintptr) int32)(unsafe.Pointer(&struct{ uintptr }{(*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods)).FxSectorSize})))(tls, pFile)
}

func sqlcipherCallDeviceCharacteristics(tls *libc.TLS, pFile uintptr) int32 {
	return (*(*func(*libc.TLS, uintptr) int32)(unsafe.Pointer(&struct{ uintptr }{(*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods)).FxDeviceCharacteristics})))(tls, pFile)
}

func sqlcipherCallShmMap(tls *libc.TLS, pFile uintptr, iPg int32, pgsz int32, flags int32, p uintptr) int32 {
	methods := (*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods))
	if methods.FxShmMap == 0 {
		return sqlite3.SQLITE_IOERR
	}
	return (*(*func(*libc.TLS, uintptr, int32, int32, int32, uintptr) int32)(unsafe.Pointer(&struct{ uintptr }{methods.FxShmMap})))(tls, pFile, iPg, pgsz, flags, p)
}

func sqlcipherCallShmLock(tls *libc.TLS, pFile uintptr, offset int32, n int32, flags int32) int32 {
	methods := (*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods))
	if methods.FxShmLock == 0 {
		return sqlite3.SQLITE_IOERR
	}
	return (*(*func(*libc.TLS, uintptr, int32, int32, int32) int32)(unsafe.Pointer(&struct{ uintptr }{methods.FxShmLock})))(tls, pFile, offset, n, flags)
}

func sqlcipherCallShmBarrier(tls *libc.TLS, pFile uintptr) {
	methods := (*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods))
	if methods.FxShmBarrier == 0 {
		return
	}
	(*(*func(*libc.TLS, uintptr))(unsafe.Pointer(&struct{ uintptr }{methods.FxShmBarrier})))(tls, pFile)
}

func sqlcipherCallShmUnmap(tls *libc.TLS, pFile uintptr, deleteFlag int32) int32 {
	methods := (*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods))
	if methods.FxShmUnmap == 0 {
		return sqlite3.SQLITE_IOERR
	}
	return (*(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&struct{ uintptr }{methods.FxShmUnmap})))(tls, pFile, deleteFlag)
}

func sqlcipherCallFetch(tls *libc.TLS, pFile uintptr, iOfst sqlite3.Sqlite3_int64, iAmt int32, pPtr uintptr) int32 {
	methods := (*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods))
	if methods.FxFetch == 0 {
		return sqlite3.SQLITE_IOERR
	}
	return (*(*func(*libc.TLS, uintptr, sqlite3.Sqlite3_int64, int32, uintptr) int32)(unsafe.Pointer(&struct{ uintptr }{methods.FxFetch})))(tls, pFile, iOfst, iAmt, pPtr)
}

func sqlcipherCallUnfetch(tls *libc.TLS, pFile uintptr, iOfst sqlite3.Sqlite3_int64, pPtr uintptr) int32 {
	methods := (*sqlite3.Tsqlite3_io_methods)(unsafe.Pointer((*sqlite3.Tsqlite3_file)(unsafe.Pointer(pFile)).FpMethods))
	if methods.FxUnfetch == 0 {
		return sqlite3.SQLITE_IOERR
	}
	return (*(*func(*libc.TLS, uintptr, sqlite3.Sqlite3_int64, uintptr) int32)(unsafe.Pointer(&struct{ uintptr }{methods.FxUnfetch})))(tls, pFile, iOfst, pPtr)
}
