# paygateway

Paket Go untuk adapter payment gateway pluggable — satu interface `Provider`,
13 adapter bawaan (12 gateway nyata + mode simulasi), **nol dependensi eksternal**
(hanya stdlib). Semua callback diverifikasi **fail-closed**: secret belum
diisi atau header signature tidak dikirim = callback ditolak, bukan lolos.

```bash
go get github.com/jhonoryza/paygateway
```

## Provider bawaan

| Nama (`Name()`) | Gateway | Verifikasi callback |
|---|---|---|
| `mock` | Simulasi (QRIS mock, tanpa gateway) | selalu menolak (mode dev) |
| `midtrans` | Midtrans Snap | SHA-512 `order_id+status_code+gross_amount+server_key` |
| `tripay` | Tripay | HMAC-SHA256 body (`X-Callback-Signature`) |
| `xendit` | Xendit Invoice | callback token (`X-Callback-Token`) |
| `doku` | DOKU Checkout API v2.1 | callback token (`X-Callback-Token`) |
| `sumopod` | Sumopod Managed Payment | webhook token (`X-Webhook-Token`) |
| `ipaymu` | iPayMu Direct API v2 | HMAC-SHA256 body (`X-Signature`, secret = nomor VA) |
| `espay` | Espay Closed Invoice VA | SHA-256 `##KEY##rq_datetime##order_id##PAYMENTREPORT##` |
| `singapay` | SingaPay Payment Link v2 | HMAC-SHA512 `POST:callback_path:token:sha256hex(body):ts` |
| `mayar` | Mayar Payment Link | HMAC-SHA256 body (`X-Signature`) |
| `lemonsqueezy` | Lemon Squeezy | HMAC-SHA256 body (`X-Signature`) |
| `creem` | Creem | HMAC-SHA256 body (`creem-signature`) |
| `polar` | Polar | svix-style `v1,base64(HMAC-SHA256(id.timestamp.body))` |

Semua adapter menerima cfg `"base_url"` untuk override ujung URL (uji menyeluruh
/E2E) dan `"environment"` (`sandbox`/`production`) untuk memilih endpoint resmi.

## Pemakaian

```go
import pay "github.com/jhonoryza/paygateway"

// 1. Buat tagihan saat order dibuat.
p, _ := pay.Get("tripay")
res, err := p.CreateCharge(pay.Charge{
    OrderID:     "1234",
    Amount:      150000,
    Title:       "Kaos Botak",
    BuyerEmail:  "pembeli@example.com",
    CallbackURL: "https://saya.example.com/callback/payment",
    ReturnURL:   "https://saya.example.com/pay/1234",
}, pay.Config{
    "api_key":       "...",
    "private_key":   "...",
    "merchant_code": "...",
    "method":        "QRIS",
    "environment":   "production",
})
// res.PayURL = halaman checkout/invoice gateway; res.Ref = id tagihan di gateway.

// 2. Terima webhook (verifikasi signature dilakukan di dalam adapter).
func callbackHandler(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
    cb, err := p.ParseCallback(r.Header, body, cfg)
    if err != nil {
        http.Error(w, "ditolak", http.StatusUnauthorized) // signature/secret bermasalah
        return
    }
    if cb.Ignore || !cb.Paid {
        return // event refund/expire/event lain — abaikan
    }
    // cb.OrderID + cb.Amount: tandai lunas di sistem Anda di sini.
    // Validasikan cb.Amount terhadap total order sendiri — pembayaran parsial
    // (mis. VA dibayar sebagian) tidak boleh dianggap lunas penuh.
}
```

Kredensial berupa `pay.Config` (`map[string]string`), bebas disimpan di mana
saja (tabel settings, env, file). Field apa saja yang wajib per provider
bisa diintrospeksi: `p.Fields()` → `[]pay.Field{Key, Label, Secret}` — cocok
untuk membangun form konfigurasi runtime (nilai `Secret` sebaiknya dimasking
saat ditampilkan).

## Mode simulasi

`pay.Mock` terdaftar sebagai provider `mock`: `CreateCharge` mengembalikan
hasil kosong tanpa memanggil gateway, `ParseCallback` selalu menolak. Cocok
untuk dev/test — alur "lunas" diisi sendiri oleh aplikasi. Deteksi:

```go
if pay.IsSimulated(p) { /* matikan endpoint webhook, sediakan tombol simulasi */ }
```

## Gateway kustom

```go
type Stripe struct{}

func (Stripe) Name() string  { return "stripe" }
func (Stripe) Label() string { return "Stripe" }
func (Stripe) Fields() []pay.Field { return []pay.Field{{Key: "api_key", Label: "API Key", Secret: true}} }
func (Stripe) CreateCharge(c pay.Charge, cfg pay.Config) (pay.Result, error) { /* ... */ }
func (Stripe) ParseCallback(h http.Header, body []byte, cfg pay.Config) (pay.Callback, error) { /* ... */ }

func init() { pay.Register(Stripe{}) }
```

## Catatan keamanan

- **Fail-closed**: secret kosong ATAU header signature hilang = error, callback
  ditolak. Tidak ada jalur "lolos bila belum dikonfigurasi".
- Perbandingan signature memakai `subtle.ConstantTimeCompare` (anti timing attack).
- `Callback.Amount` = nominal dari gateway (0 = provider tidak melaporkan).
  Selalu cocokkan dengan total order di sisi Anda sebelum menandai lunas.
- Body webhook dibaca apa adanya untuk verifikasi HMAC — teruskan body mentah
  ke `ParseCallback`, jangan re-encode terlebih dahulu.

## Kontrak provider

```go
type Provider interface {
    Name() string                                              // id stabil (disimpan di config/DB)
    Label() string                                             // nama tampil
    Fields() []Field                                           // input kredensial yang dibutuhkan
    CreateCharge(c Charge, cfg Config) (Result, error)         // buat tagihan, kembalikan URL checkout
    ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) // verifikasi + normalisasi webhook
}
```

## Test

```bash
make test    # vet + semua test
make cover   # test + race detector + coverage (total % di output akhir)
make html    # laporan coverage interaktif di browser
```

Lapisan test:

- **Kontrak `ParseCallback`** (`pay_test.go`): callback ber-signature valid
  ternormalisasi benar (`Paid`/`OrderID`/`Amount`), 16 kasus fail-closed
  (secret/header kosong = ditolak), event non-pembayaran → `Ignore`, mode simulasi.
- **Unit `CreateCharge`** (`charge_test.go`): request diverifikasi per gateway
  (path, auth, header, signature request) lewat gateway tiruan `httptest` +
  override `base_url`; response ternormalisasi ke `Result`; jalur penolakan gateway.
- **Unit registry/helper** (`helpers_test.go`): registry, `IsSimulated`, `baseURL`,
  `failClosed`, vektor HMAC/hash standar, util kecil, `postJSON`, dan kontrak
  minimum semua provider (Name stabil, Label terisi, Fields valid).
- **E2E** (`e2e_test.go`): siklus penuh per gateway — `CreateCharge` ke gateway
  tiruan, webhook ber-signature dikirim ke server webhook konsumen, konsumen
  memverifikasi via `ParseCallback` dan menandai lunas; plus `callback_path`
  kustom SingaPay dan penolakan webhook ber-signature palsu.

CI (GitHub Actions, `.github/workflows/ci.yml`) menjalankan `go vet` +
`go test -race -coverprofile` di setiap push/PR dan melaporkan total coverage.

## Lisensi

[MIT](LICENSE)
