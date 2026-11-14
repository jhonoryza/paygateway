package pay

// Unit test kontrak ParseCallback per provider: callback valid ber-signature
// harus ternormalisasi benar (Paid/OrderID/Amount), dan jalur fail-closed
// (secret belum diset / header signature tidak dikirim) harus ditolak.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func hmac256(key, msg string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

func hmac512(key, msg string) string {
	m := hmac.New(sha512.New, []byte(key))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// kasus callback valid per provider: signature dihitung sesuai kontraknya.
func validCases() []struct {
	name       string
	p          Provider
	cfg        Config
	header     map[string]string
	body       string
	wantPaid   bool
	wantOrder  string
	wantAmount int
} {
	return []struct {
		name       string
		p          Provider
		cfg        Config
		header     map[string]string
		body       string
		wantPaid   bool
		wantOrder  string
		wantAmount int
	}{
		{
			name: "midtrans", p: Midtrans{}, cfg: Config{"server_key": "mt-key"},
			header: map[string]string{},
			// signature = sha512(order_id+status_code+gross_amount+server_key)
			body: func() string {
				sig := sha512Hex("1" + "200" + "100000.00" + "mt-key")
				return `{"order_id":"1","status_code":"200","gross_amount":"100000.00","signature_key":"` + sig + `","transaction_status":"settlement","transaction_id":"t1"}`
			}(),
			wantPaid: true, wantOrder: "1", wantAmount: 100000,
		},
		{
			name: "tripay", p: Tripay{}, cfg: Config{"private_key": "tri-key"},
			header: map[string]string{"X-Callback-Signature": ""},
			body:   `{"merchant_ref":"1","status":"PAID","amount":55000}`,
			// header diisi setelah body diketahui — lihat penyesuaian di loop
			wantPaid: true, wantOrder: "1", wantAmount: 55000,
		},
		{
			name: "xendit", p: Xendit{}, cfg: Config{"callback_token": "xd-tok"},
			header:   map[string]string{"X-Callback-Token": "xd-tok"},
			body:     `{"external_id":"1","status":"PAID","id":"x1","amount":75000}`,
			wantPaid: true, wantOrder: "1", wantAmount: 75000,
		},
		{
			name: "doku", p: Doku{}, cfg: Config{"callback_token": "doku-tok"},
			header:   map[string]string{"X-Callback-Token": "doku-tok"},
			body:     `{"order":{"invoice_number":"1","amount":88000},"transaction":{"status":"SUCCESS","reference":"r1"}}`,
			wantPaid: true, wantOrder: "1", wantAmount: 88000,
		},
		{
			name: "sumopod", p: Sumopod{}, cfg: Config{"webhook_token": "whtok"},
			header:   map[string]string{"X-Webhook-Token": "whtok"},
			body:     `{"event_type":"payment.completed","data":{"payment_id":"p1","order_id":"1","status":"completed","amount":45000}}`,
			wantPaid: true, wantOrder: "1", wantAmount: 45000,
		},
		{
			name: "ipaymu", p: IPayMu{}, cfg: Config{"va": "1179000899"},
			header: map[string]string{"X-Signature": ""},
			body:   `{"status_code":1,"referenceId":"1","trx_id":99}`,
			// signature = HMAC-SHA256(body, key=va) — diisi di loop
			wantPaid: true, wantOrder: "1",
		},
		{
			name: "espay", p: Espay{}, cfg: Config{"key": "espay-key"},
			header: map[string]string{},
			body: func() string {
				sig := espaySig("espay-key", "2026-01-01 10:00:00", "1", "PAYMENTREPORT")
				form := url.Values{
					"order_id":    {"1"},
					"rq_datetime": {"2026-01-01 10:00:00"},
					"amount":      {"90000.00"},
					"signature":   {sig},
				}
				return form.Encode()
			}(),
			wantPaid: true, wantOrder: "1", wantAmount: 90000,
		},
		{
			name: "singapay", p: Singapay{}, cfg: Config{"client_secret": "sgp-secret"},
			header: map[string]string{"Authorization": "Bearer tok", "X-Timestamp": "1700000000", "X-Signature": ""},
			body:   `{"data":{"transaction":{"reff_no":"1","status":"paid"}}}`,
			// StringToSign = POST:/callback/payment:Authorization:sha256hex(body):timestamp
			wantPaid: true, wantOrder: "1",
		},
		{
			name: "mayar", p: Mayar{}, cfg: Config{"webhook_secret": "myr-secret"},
			header: map[string]string{"X-Signature": ""},
			body:   `{"event":"payment.received","data":{"description":"Order #1","id":"my1"}}`,
			// signature = HMAC-SHA256(body, secret) — diisi di loop
			wantPaid: true, wantOrder: "1",
		},
		{
			name: "creem", p: Creem{}, cfg: Config{"webhook_secret": "crm-secret"},
			header: map[string]string{"creem-signature": ""},
			body:   `{"eventType":"checkout.completed","object":{"id":"c1","metadata":{"order_id":"1"}}}`,
			// signature = HMAC-SHA256(body, secret) — diisi di loop
			wantPaid: true, wantOrder: "1",
		},
		{
			name: "polar", p: Polar{}, cfg: Config{"webhook_secret": "whsec_" + base64.StdEncoding.EncodeToString([]byte("kunci-polar-32-byte-ok-123456"))},
			header: map[string]string{"webhook-id": "whid_1", "webhook-timestamp": "1700000000", "webhook-signature": ""},
			body:   `{"type":"checkout.updated","data":{"status":"succeeded","metadata":{"order_id":"1"}}}`,
			// svix: v1,base64(HMAC-SHA256(key, id.timestamp.body)) — diisi di loop
			wantPaid: true, wantOrder: "1",
		},
		{
			name: "lemonsqueezy", p: LemonSqueezy{}, cfg: Config{"signing_secret": "ls-secret"},
			header: map[string]string{"X-Signature": ""},
			body:   `{"meta":{"event_name":"order_paid","custom_data":{"order_id":"1"}},"data":{"id":"ls1"}}`,
			// signature = HMAC-SHA256(body, secret) — diisi di loop
			wantPaid: true, wantOrder: "1",
		},
	}
}

// signBody mengisi header signature yang bergantung isi body (HMAC body).
func signBody(provider, body string, cfg Config, header map[string]string) {
	switch provider {
	case "tripay":
		header["X-Callback-Signature"] = hmacHex(cfg["private_key"], body)
	case "ipaymu":
		header["X-Signature"] = hmacHex(cfg["va"], body)
	case "mayar":
		header["X-Signature"] = hmacHex(cfg["webhook_secret"], body)
	case "creem":
		header["creem-signature"] = hmacHex(cfg["webhook_secret"], body)
	case "lemonsqueezy":
		header["X-Signature"] = hmacHex(cfg["signing_secret"], body)
	case "singapay":
		sum := sha256.Sum256([]byte(body))
		sts := strings.Join([]string{"POST", "/callback/payment", header["Authorization"], hex.EncodeToString(sum[:]), header["X-Timestamp"]}, ":")
		header["X-Signature"] = hmac512(cfg["client_secret"], sts)
	case "polar":
		raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(cfg["webhook_secret"], "whsec_"))
		signed := header["webhook-id"] + "." + header["webhook-timestamp"] + "." + body
		m := hmac.New(sha256.New, raw)
		m.Write([]byte(signed))
		header["webhook-signature"] = "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
	}
}

func TestParseCallbackValid(t *testing.T) {
	for _, tc := range validCases() {
		t.Run(tc.name, func(t *testing.T) {
			signBody(tc.p.Name(), tc.body, tc.cfg, tc.header)
			h := http.Header{}
			for k, v := range tc.header {
				h.Set(k, v)
			}
			cb, err := tc.p.ParseCallback(h, []byte(tc.body), tc.cfg)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !cb.Paid {
				t.Error("callback valid harus Paid")
			}
			if cb.OrderID != tc.wantOrder {
				t.Errorf("OrderID = %q, mau %q", cb.OrderID, tc.wantOrder)
			}
			if tc.wantAmount > 0 && cb.Amount != tc.wantAmount {
				t.Errorf("Amount = %d, mau %d", cb.Amount, tc.wantAmount)
			}
		})
	}
}

// TestParseCallbackFailClosed: secret belum dikonfigurasi ATAU header
// signature tidak dikirim — tidak boleh lolos, apa pun providernya.
func TestParseCallbackFailClosed(t *testing.T) {
	type fc struct {
		name   string
		p      Provider
		cfg    Config
		header map[string]string
		body   string
	}
	emptyHeader := map[string]string{}
	cases := []fc{
		{"mock-selalu-tolak", Mock{}, Config{}, emptyHeader, `{}`},
		{"tripay-tanpa-header", Tripay{}, Config{"private_key": "k"}, emptyHeader, `{"merchant_ref":"1","status":"PAID"}`},
		{"tripay-tanpa-secret", Tripay{}, Config{}, map[string]string{"X-Callback-Signature": "x"}, `{"merchant_ref":"1","status":"PAID"}`},
		{"xendit-tanpa-secret", Xendit{}, Config{}, map[string]string{"X-Callback-Token": "x"}, `{}`},
		{"xendit-tanpa-header", Xendit{}, Config{"callback_token": "t"}, emptyHeader, `{"external_id":"1","status":"PAID"}`},
		{"doku-tanpa-secret", Doku{}, Config{}, map[string]string{"X-Callback-Token": "x"}, `{}`},
		{"sumopod-tanpa-secret", Sumopod{}, Config{}, map[string]string{"X-Webhook-Token": "x"}, `{}`},
		{"lemonsqueezy-tanpa-header", LemonSqueezy{}, Config{"signing_secret": "s"}, emptyHeader, `{}`},
		{"espay-tanpa-secret", Espay{}, Config{}, emptyHeader, "order_id=1&signature=x"},
		{"espay-tanpa-signature", Espay{}, Config{"key": "k"}, emptyHeader, "order_id=1"},
		{"singapay-tanpa-secret", Singapay{}, Config{}, map[string]string{"X-Signature": "x"}, `{}`},
		{"mayar-tanpa-secret", Mayar{}, Config{}, map[string]string{"X-Signature": "x"}, `{}`},
		{"creem-tanpa-header", Creem{}, Config{"webhook_secret": "s"}, emptyHeader, `{}`},
		{"polar-tanpa-secret", Polar{}, Config{}, map[string]string{"webhook-signature": "x"}, `{}`},
		{"ipaymu-tanpa-header", IPayMu{}, Config{"va": "1179"}, emptyHeader, `{"status_code":1}`},
		{"midtrans-signature-salah", Midtrans{}, Config{"server_key": "k"}, emptyHeader, `{"order_id":"1","status_code":"200","gross_amount":"100000","signature_key":"ngawur","transaction_status":"settlement"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tc.header {
				h.Set(k, v)
			}
			cb, err := tc.p.ParseCallback(h, []byte(tc.body), tc.cfg)
			if err == nil {
				t.Fatalf("harus ditolak, dapat %+v", cb)
			}
			if cb.Paid {
				t.Error("callback ditolak tidak boleh Paid")
			}
		})
	}
}

// TestCallbackIgnore: event non-pembayaran diabaikan (Ignore), bukan lunas.
func TestCallbackIgnore(t *testing.T) {
	cases := []struct {
		name   string
		p      Provider
		cfg    Config
		header map[string]string
		body   string
	}{
		{"lemonsqueezy-refund", LemonSqueezy{}, Config{"signing_secret": "s"}, map[string]string{"X-Signature": ""}, `{"meta":{"event_name":"order_refunded"}}`},
		{"sumopod-expired", Sumopod{}, Config{"webhook_token": "t"}, map[string]string{"X-Webhook-Token": "t"}, `{"event_type":"payment.expired","data":{"order_id":"1","status":"expired"}}`},
		{"creem-bukan-completed", Creem{}, Config{"webhook_secret": "s"}, map[string]string{"creem-signature": ""}, `{"eventType":"refund.created"}`},
		{"polar-bukan-checkout", Polar{}, Config{"webhook_secret": "whsec_" + base64.StdEncoding.EncodeToString([]byte("kunci-polar-32-byte-ok-123456"))}, map[string]string{"webhook-id": "w", "webhook-timestamp": "t", "webhook-signature": ""}, `{"type":"order.created"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signBody(tc.p.Name(), tc.body, tc.cfg, tc.header)
			h := http.Header{}
			for k, v := range tc.header {
				h.Set(k, v)
			}
			cb, err := tc.p.ParseCallback(h, []byte(tc.body), tc.cfg)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !cb.Ignore {
				t.Errorf("event non-pembayaran harus Ignore, dapat %+v", cb)
			}
			if cb.Paid {
				t.Error("event non-pembayaran tidak boleh Paid")
			}
		})
	}
}

// TestCreateChargeMock: mode simulasi tanpa tagihan.
func TestCreateChargeMock(t *testing.T) {
	res, err := Mock{}.CreateCharge(Charge{OrderID: "1", Amount: 50000}, Config{})
	if err != nil || res.PayURL != "" {
		t.Errorf("mock harus tanpa tagihan, dapat %+v err=%v", res, err)
	}
}
