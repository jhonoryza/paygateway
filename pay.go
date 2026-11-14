// Package pay mendefinisikan kontrak provider pembayaran pluggable beserta
// adapter bawaan untuk 12 gateway (Midtrans, Tripay, Xendit, DOKU, iPayMu,
// Espay, SingaPay, Mayar, Sumopod, Lemon Squeezy, Creem, Polar) plus mode
// simulasi. Semua adapter terdaftar otomatis via init(); tambah gateway baru
// = implement satu Provider lalu daftarkan dengan Register.
package pay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Config kredensial per-provider (disimpan sebagai JSON di tabel settings).
type Config map[string]string

// Charge data tagihan yang dikirim ke gateway saat order dibuat.
type Charge struct {
	OrderID     string // id order di sistem konsumen (jadi external_id / invoice_number)
	Amount      int    // rupiah
	Title       string // nama produk (description)
	BuyerEmail  string
	CallbackURL string // URL webhook konsumen untuk notif lunas
	ReturnURL   string // halaman yang dibuka pembeli setelah bayar
}

// Result hasil pembuatan tagihan.
type Result struct {
	Ref    string // id tagihan di sisi gateway
	PayURL string // URL checkout/invoice gateway (dibuka pembeli)
	Note   string // catatan tambahan (opsional)
}

// Callback notifikasi lunas dari gateway, sudah dinormalisasi.
type Callback struct {
	OrderID string
	Paid    bool
	Ref     string
	Ignore  bool // event yang tidak relevan (mis. refund/expire) — abaikan
	// Amount nominal pembayaran dari gateway (rupiah). 0 = provider tidak
	// melaporkan nominal dengan pasti — cek kecocokan total order dilewati.
	// Pembayaran parsial (VA dibayar sebagian) TIDAK boleh dianggap lunas.
	Amount int
}

// Field satu input kredensial di konsol admin.
type Field struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Secret bool   `json:"secret"`
}

// Provider satu gateway pembayaran.
type Provider interface {
	Name() string
	Label() string
	Fields() []Field
	CreateCharge(c Charge, cfg Config) (Result, error)
	ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error)
}

var registry []Provider

// Register mendaftarkan provider (dipanggil dari init() tiap adapter).
func Register(p Provider) { registry = append(registry, p) }

// Get provider berdasarkan nama.
func Get(name string) (Provider, bool) {
	for _, p := range registry {
		if p.Name() == name {
			return p, true
		}
	}
	return nil, false
}

// List seluruh provider terdaftar.
func List() []Provider { return registry }

// IsSimulated melaporkan apakah provider adalah mode simulasi bawaan (Mock,
// tanpa gateway nyata). Konsumen biasanya mematikan endpoint webhook dan
// mengalirkan penandaan lunas sendiri saat simulasi aktif.
func IsSimulated(p Provider) bool {
	_, ok := p.(Mock)
	return ok
}

// postJSON util HTTP POST/GET JSON dengan timeout; response JSON didekode ke out.
// extraHeader opsional untuk header non-standar (x-api-key, va, X-Signature, …).
func postJSON(method, url, auth string, payload any, out any, extraHeader ...map[string]string) error {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if len(extraHeader) > 0 {
		for k, v := range extraHeader[0] {
			req.Header.Set(k, v)
		}
	}
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 400 {
		return fmt.Errorf("gateway %s: %s", res.Status, truncate(b, 200))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}
