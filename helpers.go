package pay

// Helper bersama antar adapter: HMAC/hash, verifikasi webhook fail-closed,
// pilihan base URL (override cfg "base_url" → cfg "environment"), dan util kecil.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func hmacHex(key, msg string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// failClosed menegakkan verifikasi webhook: kembalikan error (callback ditolak)
// bila secret belum dikonfigurasi ATAU header signature tidak dikirim — kosong
// di salah satu sisi tidak boleh diartikan lolos.
func failClosed(cfg Config, secretKey, headerName, headerVal, label string) (string, error) {
	secret := cfg[secretKey]
	if secret == "" {
		return "", fmt.Errorf("%s: %s belum dikonfigurasi", label, secretKey)
	}
	if headerVal == "" {
		return "", fmt.Errorf("%s: header %s wajib ada", label, headerName)
	}
	return secret, nil
}

func sha512Hex(s string) string {
	sum := sha512.Sum512([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sha256Hex: SHA-256 hex dari payload (dipakai signature request iPayMu dan
// string-to-sign webhook SingaPay).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func baseURL(cfg Config, sandbox, production string) string {
	if b := strings.TrimRight(cfg["base_url"], "/"); b != "" {
		return b
	}
	if cfg["environment"] == "production" {
		return production
	}
	return sandbox
}

// anyAmount: nominal callback bisa berupa angka JSON atau string.
func anyAmount(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		return atoiSafe(x)
	}
	return 0
}

// atoiSafe: string angka -> int, ""/tidak valid = 0 (nominal tak diketahui).
func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func uuidV4() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
