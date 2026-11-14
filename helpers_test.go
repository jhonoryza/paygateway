package pay

// Unit test registry, helper bersama, dan util HTTP pay.go.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- registry ----

func TestRegistry(t *testing.T) {
	wantNames := []string{
		"mock", "midtrans", "doku", "lemonsqueezy", "tripay", "xendit",
		"sumopod", "ipaymu", "espay", "singapay", "mayar", "creem", "polar",
	}
	got := map[string]bool{}
	for _, p := range List() {
		got[p.Name()] = true
	}
	if len(List()) < len(wantNames) {
		t.Fatalf("registry berisi %d provider, minimal %d", len(List()), len(wantNames))
	}
	for _, n := range wantNames {
		p, ok := Get(n)
		if !ok {
			t.Errorf("provider %q tidak terdaftar", n)
			continue
		}
		if p.Name() != n {
			t.Errorf("Get(%q) mengembalikan %q", n, p.Name())
		}
	}
	if _, ok := Get("tidak-ada"); ok {
		t.Error("provider tak dikenal tidak boleh ditemukan")
	}
}

type providerUji struct{}

func (providerUji) Name() string  { return "kustom-uji" }
func (providerUji) Label() string { return "Kustom" }
func (providerUji) Fields() []Field {
	return []Field{{Key: "api_key", Label: "API Key", Secret: true}}
}
func (providerUji) CreateCharge(Charge, Config) (Result, error) { return Result{}, nil }
func (providerUji) ParseCallback(http.Header, []byte, Config) (Callback, error) {
	return Callback{}, nil
}

func TestRegisterCustom(t *testing.T) {
	Register(providerUji{})
	p, ok := Get("kustom-uji")
	if !ok {
		t.Fatal("provider kustom tidak ditemukan setelah Register")
	}
	if len(p.Fields()) != 1 || p.Fields()[0].Secret != true {
		t.Errorf("Fields kustom = %+v", p.Fields())
	}
}

func TestIsSimulated(t *testing.T) {
	if !IsSimulated(Mock{}) {
		t.Error("Mock harus dianggap simulasi")
	}
	if IsSimulated(Midtrans{}) {
		t.Error("gateway nyata tidak boleh dianggap simulasi")
	}
}

// ---- baseURL ----

func TestBaseURL(t *testing.T) {
	cases := []struct {
		name, want string
		cfg        Config
	}{
		{"override-menang", "https://tiruan.local", Config{"base_url": "https://tiruan.local/"}},
		{"override-buang-slash", "https://tiruan.local", Config{"base_url": "https://tiruan.local///"}},
		{"environment-produksi", "https://api.produksi", Config{"environment": "production"}},
		{"default-sandbox", "https://api.sandbox", Config{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := baseURL(tc.cfg, "https://api.sandbox", "https://api.produksi"); got != tc.want {
				t.Errorf("baseURL = %q, mau %q", got, tc.want)
			}
		})
	}
}

// ---- failClosed ----

func TestFailClosed(t *testing.T) {
	if _, err := failClosed(Config{}, "secret", "X-Sig", "abc", "uji"); err == nil {
		t.Error("secret kosong harus error")
	}
	if _, err := failClosed(Config{"secret": "k"}, "secret", "X-Sig", "", "uji"); err == nil {
		t.Error("header kosong harus error")
	}
	got, err := failClosed(Config{"secret": "kunci"}, "secret", "X-Sig", "abc", "uji")
	if err != nil || got != "kunci" {
		t.Errorf("dapat (%q, %v), mau (\"kunci\", nil)", got, err)
	}
}

// ---- crypto helpers: vektor standar ----

func TestCryptoVectors(t *testing.T) {
	// HMAC-SHA256 vektor RFC 4231-ish (key "key", pesan "The quick brown fox jumps over the lazy dog")
	if got := hmacHex("key", "The quick brown fox jumps over the lazy dog"); got != "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8" {
		t.Errorf("hmacHex = %s", got)
	}
	// SHA-512("abc")
	want512 := "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
		"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
	if got := sha512Hex("abc"); got != want512 {
		t.Errorf("sha512Hex = %s", got)
	}
	// SHA-256("")
	if got := sha256Hex(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("sha256Hex = %s", got)
	}
}

// ---- util kecil ----

func TestAnyAmount(t *testing.T) {
	cases := []struct {
		in   any
		want int
	}{
		{float64(150000), 150000},
		{float64(150000.50), 150000}, // dibulatkan ke bawah
		{"150000", 150000},
		{" 55000 ", 55000},
		{"bukan angka", 0},
		{nil, 0},
		{true, 0},
	}
	for _, tc := range cases {
		if got := anyAmount(tc.in); got != tc.want {
			t.Errorf("anyAmount(%v) = %d, mau %d", tc.in, got, tc.want)
		}
	}
}

func TestAtoiSafe(t *testing.T) {
	for in, want := range map[string]int{"42": 42, "": 0, "x": 0, " 7 ": 7} {
		if got := atoiSafe(in); got != want {
			t.Errorf("atoiSafe(%q) = %d, mau %d", in, got, want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "ketiga"); got != "ketiga" {
		t.Errorf("firstNonEmpty = %q", got)
	}
	if got := firstNonEmpty("", "kedua", "ketiga"); got != "kedua" {
		t.Errorf("firstNonEmpty = %q", got)
	}
	if got := firstNonEmpty(); got != "" {
		t.Errorf("firstNonEmpty() = %q", got)
	}
}

func TestUUIDV4(t *testing.T) {
	for i := 0; i < 50; i++ {
		u := uuidV4()
		if len(u) != 36 || u[8] != '-' || u[13] != '-' || u[18] != '-' || u[23] != '-' {
			t.Fatalf("format uuid salah: %q", u)
		}
		if u[14] != '4' {
			t.Fatalf("versi bukan 4: %q", u)
		}
		if u[19] != '8' && u[19] != '9' && u[19] != 'a' && u[19] != 'b' {
			t.Fatalf("varian salah: %q", u)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate([]byte("abcdef"), 3); got != "abc" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate([]byte("ab"), 3); got != "ab" {
		t.Errorf("truncate = %q", got)
	}
}

// ---- postJSON ----

func TestPostJSON(t *testing.T) {
	t.Run("sukses-dengan-header", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method = %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
			}
			if r.Header.Get("X-Custom") != "nilai" {
				t.Errorf("X-Custom = %q", r.Header.Get("X-Custom"))
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
			}
			fmt.Fprint(w, `{"halo":"dunia"}`)
		}))
		defer s.Close()

		var out struct {
			Halo string `json:"halo"`
		}
		err := postJSON("POST", s.URL, "Bearer tok", map[string]string{"a": "b"}, &out,
			map[string]string{"X-Custom": "nilai"})
		if err != nil {
			t.Fatalf("postJSON: %v", err)
		}
		if out.Halo != "dunia" {
			t.Errorf("out = %+v", out)
		}
	})

	t.Run("http-400", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"pesan":"ditolak"}`)
		}))
		defer s.Close()
		err := postJSON("POST", s.URL, "", nil, nil)
		if err == nil || !strings.Contains(err.Error(), "400") {
			t.Errorf("harus error ber-status 400, dapat %v", err)
		}
	})

	t.Run("get-tanpa-payload", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("method = %s", r.Method)
			}
			fmt.Fprint(w, `{"ok":true}`)
		}))
		defer s.Close()
		var out struct {
			OK bool `json:"ok"`
		}
		if err := postJSON("GET", s.URL, "", nil, &out); err != nil || !out.OK {
			t.Errorf("postJSON GET: %+v err=%v", out, err)
		}
	})

	t.Run("json-rusak", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `bukan json`)
		}))
		defer s.Close()
		var out map[string]any
		if err := postJSON("POST", s.URL, "", nil, &out); err == nil {
			t.Error("response bukan JSON harus error")
		}
	})
}

// TestProviderContract: kontrak minimum semua provider terdaftar — Name stabil
// (id disimpan di config konsumen), Label tampil, Fields bervalidasi (key unik,
// label terisi). Sekalian menutup Label()/Fields() tiap adapter.
func TestProviderContract(t *testing.T) {
	bawaan := map[string]bool{
		"mock": true, "midtrans": true, "doku": true, "lemonsqueezy": true,
		"tripay": true, "xendit": true, "sumopod": true, "ipaymu": true,
		"espay": true, "singapay": true, "mayar": true, "creem": true, "polar": true,
	}
	for _, p := range List() {
		t.Run(p.Name(), func(t *testing.T) {
			if p.Name() == "" || strings.ContainsAny(p.Name(), " /") {
				t.Errorf("Name() = %q — harus id stabil tanpa spasi", p.Name())
			}
			if p.Label() == "" {
				t.Error("Label() tidak boleh kosong")
			}
			keys := map[string]bool{}
			for _, f := range p.Fields() {
				if f.Key == "" {
					t.Errorf("Field key kosong: %+v", f)
				}
				if keys[f.Key] {
					t.Errorf("Field key duplikat: %q", f.Key)
				}
				keys[f.Key] = true
				if f.Label == "" {
					t.Errorf("Field %q tanpa label", f.Key)
				}
			}
			// semua gateway nyata menyediakan override base_url untuk E2E;
			// override berisi ujung URL internal — selalu Secret.
			// (mock dan provider kustom pihak ketiga dikecualikan)
			if p.Name() != "mock" && bawaan[p.Name()] {
				if _, ok := keys["base_url"]; !ok {
					t.Errorf("provider %q tidak punya field base_url", p.Name())
				}
			}
		})
	}
}
