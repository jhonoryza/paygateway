# AGENTS.md — paygateway (root DOX, repo `jhonoryza/paygateway`)

## Purpose

`paygateway`: package Go publik untuk adapter payment gateway pluggable — satu
interface `pay.Provider` + 13 adapter bawaan (12 gateway nyata: Midtrans,
Tripay, Xendit, DOKU, Sumopod, iPayMu, Espay, SingaPay, Mayar, Lemon Squeezy,
Creem, Polar; plus mode simulasi `mock`). Module `github.com/jhonoryza/paygateway`,
Go 1.25, **nol dependensi eksternal** (hanya stdlib), MIT. Semua verifikasi
callback fail-closed. Dikonsumsi aplikasi via `pay.Get(name)` + `CreateCharge`
→ tampilkan `Result.PayURL` → `ParseCallback` di handler webhook.

## Ownership

- Repo: `github.com/jhonoryza/paygateway` (public, MIT). Maintainer tunggal
  (fajar / jhonoryza).
- Ini adalah library publik yang di-`go get` aplikasi lain: perubahan pada
  permukaan API ekspor adalah breaking change — keputusan desain ditandatangani
  user di percakapan; agent mengeksekusi mengikuti kontrak di bawah.

## Local Contracts (repo-wide, binding)

1. **Nol dependensi eksternal** — `go.mod` tanpa `require`. Menambah dependensi
   apa pun (termasuk indirect) = perubahan kontrak, wajib persetujuan user.
2. **Verifikasi callback fail-closed** — secret belum dikonfigurasi ATAU header
   signature tidak dikirim = callback ditolak (helper `failClosed`); kosong di
   satu sisi tidak pernah diartikan lolos. Perbandingan signature selalu
   `subtle.ConstantTimeCompare` (anti timing attack). Dilarang menambah jalur
   "lolos bila belum dikonfigurasi" di adapter mana pun.
3. **Adapter self-register** — satu gateway = satu file `<nama>.go`, tipe value
   struct kosong, `init()` → `Register(...)` (gaya `database/sql`). `Name()`
   adalah id stabil yang disimpan di DB konsumen: dilarang mengubah nilai
   `Name()` adapter yang sudah dirilis.
4. **Semantik `Callback`** — `Amount` 0 = gateway tidak melaporkan nominal
   (konsumen wajib cocokkan total order sendiri); pembayaran parsial (VA
   dibayar sebagian) tidak boleh `Paid=true`. Event non-pembayaran
   (refund/expire/failed/event tak dikenal) → `Callback{Ignore: true}`, bukan
   error dan bukan `Paid=false` semata.
5. **Kunci cfg seragam** — `base_url` (override endpoint penuh; dipakai test
   httptest) dan `environment` (`sandbox`/`production`) dipilih via helper
   `baseURL`; `callback_path` hanya dipakai SingaPay. Body webhook diverifikasi
   apa adanya — HMAC dihitung atas byte mentah, tanpa re-encode.
6. **Permukaan publik adalah API library** — `Charge`, `Result`, `Callback`,
   `Config`, `Field`, `Provider`, `Register/Get/List`, `IsSimulated`, `Mock`.
   Menambah field/method bersifat additive; mengubah/menghapus = breaking,
   jangan lakukan tanpa persetujuan user.

## Work Guidance

- Satu file per gateway; helper bersama hanya di `helpers.go` (HMAC/hash,
  `failClosed`, `baseURL`, `anyAmount`, `firstNonEmpty`, `uuidV4`); plumbing
  HTTP lewat `postJSON` di `pay.go` (timeout 15s, response dibaca
  `LimitReader` 1MB, status ≥ 400 → error berisi cuplikan 200 byte).
- Komentar kode & README bahasa Indonesia; header file adapter memuat kontrak
  API gateway yang dirujuk (lihat `singapay.go`).
- Gateway baru wajib lengkap 4 lapisan test: fail-closed + valid `ParseCallback`
  di `pay_test.go`; unit `CreateCharge` dengan gateway tiruan `httptest` +
  override `base_url` di `charge_test.go`; kontrak minimum (`Name` stabil,
  `Label` terisi, `Fields` valid) di `TestProviderContract` (`helpers_test.go`);
  siklus penuh CreateCharge→webhook→ParseCallback di `e2e_test.go`. Tambah
  baris tabel di README (`Provider bawaan`).
- Endpoint gateway nyata tidak pernah dipanggil di test — selalu tiruan
  `httptest` + `base_url`.

## Verification

- `make test` — `go vet ./...` + semua test; wajib hijau sebelum commit.
- `make cover` — test + race detector + coverage (total % di baris terakhir);
  `make html` untuk laporan interaktif.
- CI (`.github/workflows/ci.yml`) menjalankan vet + `go test -race
  -coverprofile` per push/PR.

## Child DOX Index

- Belum ada child DOX — repo flat, satu package `pay`, semua file di root.
  Buat child `AGENTS.md` hanya bila sebuah folder jadi boundary durable
  (mis. adapter dipecah ke direktori sendiri atau muncul folder contoh/dok).
