package pay

// End-to-end: satu siklus penuh per provider tanpa stub —
//   1. CreateCharge dipanggil untuk sungguhan, request HTTP masuk ke gateway
//      tiruan (httptest, lewat override cfg "base_url");
//   2. gateway tiruan "mengirim" webhook ber-signature ke server webhook
//      konsumen (httptest kedua);
//   3. konsumen mem-verifikasi via ParseCallback dan menandai order lunas.
// Semua verifikasi signature memakai logika kontrak asli (validCases/signBody),
// bukan replikasi.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// chargeResponse: response tagihan tiruan per provider (sesuai kontrak API
// masing-masing); path dipakai untuk membedakan dua endpoint SingaPay.
func chargeResponse(name, path string) string {
	switch name {
	case "midtrans":
		return `{"redirect_url":"https://gw/pay/1","token":"tok-1"}`
	case "tripay":
		return `{"success":true,"data":{"reference":"REF-1","checkout_url":"https://gw/tri"}}`
	case "xendit":
		return `{"id":"inv-1","invoice_url":"https://gw/xd"}`
	case "doku":
		return `{"order":{"invoice_number":"INV-1"},"response":{"payment":{"url":"https://gw/doku"}}}`
	case "sumopod":
		return `{"payment_link_url":"https://gw/sp","payment_code":"PC-1"}`
	case "ipaymu":
		return `{"Status":200,"Data":{"Url":"https://gw/ipm","TransactionId":"TRX-1"}}`
	case "espay":
		return `{"error_code":"0000","va_number":"880800000001"}`
	case "mayar":
		return `{"data":{"id":"pay-1","link":"https://gw/myr"}}`
	case "lemonsqueezy":
		return `{"data":{"id":"ck-1","attributes":{"url":"https://gw/ls"}}}`
	case "creem":
		return `{"id":"ch-1","checkout_url":"https://gw/creem"}`
	case "polar":
		return `{"id":"po-1","url":"https://gw/polar"}`
	}
	if name == "singapay" && strings.Contains(path, "/access-token/") {
		return `{"access_token":"tok-sgp"}`
	}
	return `{"data":{"payment_url":"https://gw/sgp"}}`
}

func TestE2E(t *testing.T) {
	for _, tc := range validCases() {
		t.Run(tc.name, func(t *testing.T) {
			gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(chargeResponse(tc.name, r.URL.Path)))
			}))
			defer gw.Close()

			cfg := Config{}
			for k, v := range tc.cfg {
				cfg[k] = v
			}
			cfg["base_url"] = gw.URL

			lunas := make(chan Callback, 1)
			ditolak := make(chan int, 1)
			consumer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				cb, err := tc.p.ParseCallback(r.Header, b, cfg)
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					ditolak <- 1
					return
				}
				if !cb.Ignore && cb.Paid {
					lunas <- cb
				}
				w.Write([]byte(`{"ok":true}`))
			}))
			defer consumer.Close()

			res, err := tc.p.CreateCharge(Charge{
				OrderID:     "1",
				Amount:      150000,
				Title:       "Produk Uji",
				BuyerEmail:  "pembeli@example.com",
				CallbackURL: consumer.URL + "/callback/payment",
				ReturnURL:   consumer.URL + "/pay/1",
			}, cfg)
			if err != nil {
				t.Fatalf("CreateCharge: %v", err)
			}
			if res.Ref == "" {
				t.Error("Ref tidak boleh kosong setelah tagihan dibuat")
			}
			// Espay berupa VA tanpa halaman checkout — PayURL memang kosong.
			if res.PayURL == "" && tc.name != "espay" {
				t.Errorf("PayURL kosong: %+v", res)
			}

			// Gateway "memberi tahu": webhook ber-signature dikirim ke konsumen.
			header := map[string]string{}
			for k, v := range tc.header {
				header[k] = v
			}
			signBody(tc.name, tc.body, cfg, header)
			req, _ := http.NewRequest("POST", consumer.URL+"/callback/payment", strings.NewReader(tc.body))
			for k, v := range header {
				req.Header.Set(k, v)
			}
			rs, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("kirim webhook: %v", err)
			}
			rs.Body.Close()
			select {
			case cb := <-lunas:
				if !cb.Paid || cb.OrderID != tc.wantOrder {
					t.Errorf("callback = %+v, mau order %q lunas", cb, tc.wantOrder)
				}
				if tc.wantAmount > 0 && cb.Amount != tc.wantAmount {
					t.Errorf("Amount = %d, mau %d", cb.Amount, tc.wantAmount)
				}
			case <-ditolak:
				t.Fatal("webhook valid harusnya diterima, ternyata ditolak")
			case <-time.After(3 * time.Second):
				t.Fatal("webhook tidak pernah memproses order")
			}
		})
	}
}

// TestE2ESingapayCustomPath: cfg "callback_path" mengubah string-to-sign —
// webhook ke path lain dari default tetap terverifikasi.
func TestE2ESingapayCustomPath(t *testing.T) {
	const path = "/webhook/sgp"
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(chargeResponse("singapay", r.URL.Path)))
	}))
	defer gw.Close()

	cfg := Config{"client_secret": "sgp-secret", "base_url": gw.URL, "callback_path": path}
	p := Singapay{}

	lunas := make(chan Callback, 1)
	consumer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		cb, err := p.ParseCallback(r.Header, b, cfg)
		if err != nil {
			t.Errorf("parse: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if cb.Paid {
			lunas <- cb
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer consumer.Close()

	if _, err := p.CreateCharge(Charge{OrderID: "9", Amount: 25000, CallbackURL: consumer.URL + path}, cfg); err != nil {
		t.Fatalf("CreateCharge: %v", err)
	}

	body := `{"data":{"transaction":{"reff_no":"9","status":"paid"}}}`
	ts := "1700000009"
	auth := "Bearer tok-sgp"
	sig := hmac512("sgp-secret", strings.Join([]string{"POST", path, auth, sha256Hex([]byte(body)), ts}, ":"))
	req, _ := http.NewRequest("POST", consumer.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", auth)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sig)
	rs, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("kirim webhook: %v", err)
	}
	rs.Body.Close()
	select {
	case cb := <-lunas:
		if !cb.Paid || cb.OrderID != "9" {
			t.Errorf("callback = %+v", cb)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook tidak pernah memproses order")
	}
}

// TestE2EWebhookTandaTanganSalah: webhook tanpa signature valid harus ditolak
// oleh konsumen (401), order tidak lunas.
func TestE2EWebhookTandaTanganSalah(t *testing.T) {
	ditolak := make(chan bool, 1)
	consumer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if _, err := (Tripay{}).ParseCallback(r.Header, b, Config{"private_key": "tri-key"}); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			ditolak <- true
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer consumer.Close()

	rs, err := http.Post(consumer.URL+"/callback/payment", "application/json",
		strings.NewReader(`{"merchant_ref":"1","status":"PAID","amount":55000}`))
	if err != nil {
		t.Fatalf("kirim: %v", err)
	}
	rs.Body.Close()
	select {
	case <-ditolak:
		// benar: signature palsu ditolak fail-closed
	case <-time.After(3 * time.Second):
		t.Fatal("webhook tanda-tangan-salah harusnya ditolak")
	}
}
