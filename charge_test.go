package pay

// Unit test CreateCharge per provider: gateway tiruan (httptest) di-override
// lewat cfg "base_url" — request diverifikasi (path, auth, header, payload,
// signature request), response gateway diverifikasi ternormalisasi benar ke
// Result{Ref, PayURL}.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const ujiAmount = 150000

// ujiCharge Charge standar untuk semua test CreateCharge.
func ujiCharge(callback, ret string) Charge {
	return Charge{
		OrderID:     "1",
		Amount:      ujiAmount,
		Title:       "Produk Uji",
		BuyerEmail:  "pembeli@example.com",
		CallbackURL: callback,
		ReturnURL:   ret,
	}
}

// bacaBody: baca body request habis untuk diverifikasi.
func bacaBody(r *http.Request) []byte {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	return b
}

func TestCreateCharge(t *testing.T) {
	cases := []struct {
		name    string
		p       Provider
		cfg     Config
		verify  func(t *testing.T, r *http.Request, body []byte)
		resp    string
		wantRef string
		wantURL string
	}{
		{
			name: "midtrans", p: Midtrans{}, cfg: Config{"server_key": "mt-key"},
			verify: func(t *testing.T, r *http.Request, body []byte) {
				if r.URL.Path != "/snap/v1/transactions" {
					t.Errorf("path = %s", r.URL.Path)
				}
				if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("mt-key:")); r.Header.Get("Authorization") != want {
					t.Errorf("auth = %q", r.Header.Get("Authorization"))
				}
				var in struct {
					TD struct {
						OrderID string `json:"order_id"`
						Gross   int    `json:"gross_amount"`
					} `json:"transaction_details"`
				}
				json.Unmarshal(body, &in)
				if in.TD.OrderID != "1" || in.TD.Gross != ujiAmount {
					t.Errorf("transaction_details = %+v", in.TD)
				}
			},
			resp:    `{"redirect_url":"https://gw/pay/1","token":"tok-1"}`,
			wantRef: "1", wantURL: "https://gw/pay/1",
		},
		{
			name: "tripay", p: Tripay{}, cfg: Config{"api_key": "tri-api", "private_key": "tri-key", "merchant_code": "MCH123"},
			verify: func(t *testing.T, r *http.Request, body []byte) {
				if r.URL.Path != "/transaction/create" {
					t.Errorf("path = %s", r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer tri-api" {
					t.Errorf("auth = %q", r.Header.Get("Authorization"))
				}
				var in struct {
					Method      string `json:"method"`
					MerchantRef string `json:"merchant_ref"`
					Amount      int    `json:"amount"`
					Signature   string `json:"signature"`
				}
				json.Unmarshal(body, &in)
				if in.Method != "QRIS" { // default bila cfg method kosong
					t.Errorf("method = %q", in.Method)
				}
				want := hmacHex("tri-key", "MCH123"+"1"+strconv.Itoa(ujiAmount))
				if in.Signature != want {
					t.Errorf("signature request = %q, mau %q", in.Signature, want)
				}
			},
			resp:    `{"success":true,"data":{"reference":"REF-1","checkout_url":"https://gw/tri"}}`,
			wantRef: "REF-1", wantURL: "https://gw/tri",
		},
		{
			name: "xendit", p: Xendit{}, cfg: Config{"api_key": "xd-api"},
			verify: func(t *testing.T, r *http.Request, body []byte) {
				if r.URL.Path != "/v2/invoices" {
					t.Errorf("path = %s", r.URL.Path)
				}
				if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("xd-api:")); r.Header.Get("Authorization") != want {
					t.Errorf("auth = %q", r.Header.Get("Authorization"))
				}
				var in struct {
					ExternalID string `json:"external_id"`
					Amount     int    `json:"amount"`
					Redirect   string `json:"success_redirect_url"`
				}
				json.Unmarshal(body, &in)
				if in.ExternalID != "1" || in.Amount != ujiAmount || in.Redirect != "https://saya.id/pay/1" {
					t.Errorf("body = %+v", in)
				}
			},
			resp:    `{"id":"inv-1","invoice_url":"https://gw/xd"}`,
			wantRef: "inv-1", wantURL: "https://gw/xd",
		},
		{
			name: "lemonsqueezy", p: LemonSqueezy{}, cfg: Config{"api_key": "ls-api", "store_id": "456", "variant_id": "789"},
			verify: func(t *testing.T, r *http.Request, body []byte) {
				if r.URL.Path != "/v1/checkouts" {
					t.Errorf("path = %s", r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer ls-api" {
					t.Errorf("auth = %q", r.Header.Get("Authorization"))
				}
				var in struct {
					Data struct {
						Type string `json:"type"`
						Attr struct {
							CO struct {
								Custom map[string]string `json:"custom"`
							} `json:"checkout_data"`
						} `json:"attributes"`
						Rel struct {
							Store struct {
								Data struct {
									ID string `json:"id"`
								} `json:"data"`
							} `json:"store"`
							Variant struct {
								Data struct {
									ID string `json:"id"`
								} `json:"data"`
							} `json:"variant"`
						} `json:"relationships"`
					} `json:"data"`
				}
				json.Unmarshal(body, &in)
				if in.Data.Type != "checkouts" || in.Data.Attr.CO.Custom["order_id"] != "1" ||
					in.Data.Rel.Store.Data.ID != "456" || in.Data.Rel.Variant.Data.ID != "789" {
					t.Errorf("body JSON:API = %s", body)
				}
			},
			resp:    `{"data":{"id":"ck-1","attributes":{"url":"https://gw/ls"}}}`,
			wantRef: "ck-1", wantURL: "https://gw/ls",
		},
		{
			name: "doku", p: Doku{}, cfg: Config{"client_id": "doku-client", "secret_key": "doku-secret"},
			verify: func(t *testing.T, r *http.Request, body []byte) {
				if r.URL.Path != "/orders/v2.1/order" {
					t.Errorf("path = %s", r.URL.Path)
				}
				m := hmac.New(sha256.New, []byte("doku-secret"))
				m.Write([]byte("doku-client" + r.Header.Get("Request-Id") + r.Header.Get("Request-Timestamp") + string(body)))
				want := base64.StdEncoding.EncodeToString(m.Sum(nil))
				if r.Header.Get("Signature") != want {
					t.Error("signature request doku salah")
				}
			},
			resp:    `{"order":{"invoice_number":"INV-1"},"response":{"payment":{"url":"https://gw/doku"}}}`,
			wantRef: "INV-1", wantURL: "https://gw/doku",
		},
		{
			name: "sumopod", p: Sumopod{}, cfg: Config{"api_key": "sp-key"},
			verify: func(t *testing.T, r *http.Request, body []byte) {
				if r.URL.Path != "/api/v1/payments" {
					t.Errorf("path = %s", r.URL.Path)
				}
				if r.Header.Get("X-Api-Key") != "sp-key" {
					t.Errorf("X-Api-Key = %q", r.Header.Get("X-Api-Key"))
				}
				var in struct {
					OrderID string `json:"order_id"`
					Amount  int    `json:"amount"`
					Ccy     string `json:"currency"`
					Method  string `json:"payment_method_type_code"`
				}
				json.Unmarshal(body, &in)
				if in.OrderID != "1" || in.Amount != ujiAmount || in.Ccy != "IDR" || in.Method != "QRIS" {
					t.Errorf("body = %+v", in)
				}
			},
			resp:    `{"payment_link_url":"https://gw/sp","payment_code":"PC-1"}`,
			wantRef: "PC-1", wantURL: "https://gw/sp",
		},
		{
			// bentuk response alternatif: url/code dibungkus "data" (lihat ParseCallback)
			name: "sumopod-nested", p: Sumopod{}, cfg: Config{"api_key": "sp-key", "payment_method_type_code": "BRIVA"},
			verify: func(t *testing.T, r *http.Request, body []byte) {
				var in struct {
					Method string `json:"payment_method_type_code"`
				}
				json.Unmarshal(body, &in)
				if in.Method != "BRIVA" {
					t.Errorf("method = %q", in.Method)
				}
			},
			resp:    `{"data":{"payment_link_url":"https://gw/sp2","payment_code":"PC-2"}}`,
			wantRef: "PC-2", wantURL: "https://gw/sp2",
		},
		{
			name: "ipaymu", p: IPayMu{}, cfg: Config{"api_key": "ipm-api", "va": "1179000899"},
			verify: func(t *testing.T, r *http.Request, body []byte) {
				if r.URL.Path != "/api/v2/payment" {
					t.Errorf("path = %s", r.URL.Path)
				}
				want := hmacHex("ipm-api", "POST:1179000899:"+sha256Hex(body)+":ipm-api")
				if r.Header.Get("signature") != want {
					t.Error("signature request ipaymu salah")
				}
				var in struct {
					Price  []string `json:"price"`
					RefID  string   `json:"referenceId"`
					Notify string   `json:"notifyUrl"`
				}
				json.Unmarshal(body, &in)
				if len(in.Price) != 1 || in.Price[0] != "150000" || in.RefID != "1" || in.Notify != "https://saya.id/callback/payment" {
					t.Errorf("body = %+v", in)
				}
			},
			resp:    `{"Status":200,"Data":{"Url":"https://gw/ipm","TransactionId":"TRX-1"}}`,
			wantRef: "TRX-1", wantURL: "https://gw/ipm",
		},
		{
			name: "espay", p: Espay{}, cfg: Config{"key": "espay-key", "comm_code": "COMM1", "password": "pwd"},
			verify: func(t *testing.T, r *http.Request, body []byte) {
				if r.URL.Path != "/rest/merchantpg/sendinvoice" {
					t.Errorf("path = %s", r.URL.Path)
				}
				vals, err := url.ParseQuery(string(body))
				if err != nil {
					t.Fatalf("form: %v", err)
				}
				want := espaySig("espay-key", vals.Get("rq_uuid"), vals.Get("rq_datetime"), "1", "150000.00", "IDR", "COMM1", "SENDINVOICE")
				if vals.Get("signature") != want {
					t.Error("signature request espay salah")
				}
				if vals.Get("amount") != "150000.00" {
					t.Errorf("amount = %q", vals.Get("amount"))
				}
			},
			// VA tanpa halaman checkout: PayURL kosong, Ref berisi nomor VA
			resp:    `{"error_code":"0000","va_number":"880800000001"}`,
			wantRef: "VA 880800000001", wantURL: "",
		},
		{
			name: "mayar", p: Mayar{}, cfg: Config{"api_key": "myr-api"},
			verify: func(t *testing.T, r *http.Request, body []byte) {
				if r.URL.Path != "/hl/v2/products/payment-link/create" {
					t.Errorf("path = %s", r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer myr-api" {
					t.Errorf("auth = %q", r.Header.Get("Authorization"))
				}
				var in struct {
					Name        string `json:"name"`
					Description string `json:"description"`
				}
				json.Unmarshal(body, &in)
				if !strings.Contains(in.Description, "Order #1") || !strings.Contains(in.Name, "1") {
					t.Errorf("name/description = %q / %q", in.Name, in.Description)
				}
			},
			resp:    `{"data":{"id":"pay-1","link":"https://gw/myr"}}`,
			wantRef: "pay-1", wantURL: "https://gw/myr",
		},
		{
			name: "creem", p: Creem{}, cfg: Config{"api_key": "crm-api", "product_id": "prod_1"},
			verify: func(t *testing.T, r *http.Request, body []byte) {
				if r.URL.Path != "/v1/checkouts" {
					t.Errorf("path = %s", r.URL.Path)
				}
				if r.Header.Get("x-api-key") != "crm-api" {
					t.Errorf("x-api-key = %q", r.Header.Get("x-api-key"))
				}
				var in struct {
					ProductID string         `json:"product_id"`
					Metadata  map[string]any `json:"metadata"`
				}
				json.Unmarshal(body, &in)
				if in.ProductID != "prod_1" || in.Metadata["order_id"] != "1" {
					t.Errorf("body = %+v", in)
				}
			},
			resp:    `{"id":"ch-1","checkout_url":"https://gw/creem"}`,
			wantRef: "ch-1", wantURL: "https://gw/creem",
		},
		{
			name: "polar", p: Polar{}, cfg: Config{"api_key": "polar-pat", "product_id": "prod-uuid"},
			verify: func(t *testing.T, r *http.Request, body []byte) {
				if r.URL.Path != "/v1/checkouts" {
					t.Errorf("path = %s", r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer polar-pat" {
					t.Errorf("auth = %q", r.Header.Get("Authorization"))
				}
				var in struct {
					Products []string `json:"products"`
					Ccy      string   `json:"currency"`
				}
				json.Unmarshal(body, &in)
				if len(in.Products) != 1 || in.Products[0] != "prod-uuid" || in.Ccy != "idr" {
					t.Errorf("body = %+v", in)
				}
			},
			resp:    `{"id":"po-1","url":"https://gw/polar"}`,
			wantRef: "po-1", wantURL: "https://gw/polar",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b := bacaBody(r)
				if tc.verify != nil {
					tc.verify(t, r, b)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(tc.resp))
			}))
			defer gw.Close()

			cfg := Config{"base_url": gw.URL}
			for k, v := range tc.cfg {
				cfg[k] = v
			}
			res, err := tc.p.CreateCharge(ujiCharge("https://saya.id/callback/payment", "https://saya.id/pay/1"), cfg)
			if err != nil {
				t.Fatalf("CreateCharge: %v", err)
			}
			if res.Ref != tc.wantRef {
				t.Errorf("Ref = %q, mau %q", res.Ref, tc.wantRef)
			}
			if res.PayURL != tc.wantURL {
				t.Errorf("PayURL = %q, mau %q", res.PayURL, tc.wantURL)
			}
		})
	}
}

// TestCreateChargeSingapay: dua tahap (token B2B + payment link) di satu
// gateway tiruan; signature token diverifikasi.
func TestCreateChargeSingapay(t *testing.T) {
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/access-token/") {
			want := hmacSha512Hex("sgp-secret", "sgp-client_sgp-secret_"+time.Now().In(time.FixedZone("WIB", 7*3600)).Format("20060102"))
			if r.Header.Get("X-Signature") != want {
				t.Error("signature token singapay salah")
			}
			if r.Header.Get("X-CLIENT-ID") != "sgp-client" {
				t.Errorf("X-CLIENT-ID = %q", r.Header.Get("X-CLIENT-ID"))
			}
			w.Write([]byte(`{"access_token":"tok-sgp"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok-sgp" {
			t.Errorf("auth payment-link = %q", r.Header.Get("Authorization"))
		}
		if !strings.HasSuffix(r.URL.Path, "/payment-link/acc-1") {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`{"data":{"payment_url":"https://gw/sgp"}}`))
	}))
	defer gw.Close()

	res, err := Singapay{}.CreateCharge(ujiCharge("https://saya.id/callback/payment", "https://saya.id/pay/1"),
		Config{"base_url": gw.URL, "client_id": "sgp-client", "client_secret": "sgp-secret", "partner_id": "PID", "account_id": "acc-1"})
	if err != nil {
		t.Fatalf("CreateCharge: %v", err)
	}
	if res.Ref != "1" || res.PayURL != "https://gw/sgp" {
		t.Errorf("Result = %+v", res)
	}
}

// TestCreateChargeErrors: gateway menolak / response tidak lengkap — harus
// error, bukan Result setengah jadi.
func TestCreateChargeErrors(t *testing.T) {
	cases := []struct {
		name   string
		p      Provider
		cfg    Config
		status int
		resp   string
	}{
		{"tripay-ditolak", Tripay{}, Config{}, 200, `{"success":false}`},
		{"xendit-http-400", Xendit{}, Config{}, 400, `{"error":"bad"}`},
		{"midtrans-http-500", Midtrans{}, Config{}, 500, `oops`},
		{"sumopod-tanpa-url", Sumopod{}, Config{}, 200, `{"payment_code":"PC"}`},
		{"ipaymu-tanpa-url", IPayMu{}, Config{}, 200, `{"Status":200,"Data":{"TransactionId":"T"}}`},
		{"espay-ditolak", Espay{}, Config{}, 200, `{"error_code":"0001","error_message":"gagal"}`},
		{"mayar-tanpa-link", Mayar{}, Config{}, 200, `{"data":{"id":"x"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.resp))
			}))
			defer gw.Close()
			cfg := Config{"base_url": gw.URL}
			for k, v := range tc.cfg {
				cfg[k] = v
			}
			if _, err := tc.p.CreateCharge(ujiCharge("", ""), cfg); err == nil {
				t.Error("harus error, dapat nil")
			}
		})
	}
}

// TestCreateChargeSingapayErrors: access token kosong dan payment_url kosong.
func TestCreateChargeSingapayErrors(t *testing.T) {
	t.Run("tanpa-access-token", func(t *testing.T) {
		gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"error":"denied"}`))
		}))
		defer gw.Close()
		if _, err := (Singapay{}).CreateCharge(ujiCharge("", ""), Config{"base_url": gw.URL}); err == nil {
			t.Error("harus error (token kosong)")
		}
	})
	t.Run("tanpa-payment-url", func(t *testing.T) {
		gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/access-token/") {
				w.Write([]byte(`{"access_token":"tok"}`))
				return
			}
			w.Write([]byte(`{"data":{}}`))
		}))
		defer gw.Close()
		if _, err := (Singapay{}).CreateCharge(ujiCharge("", ""), Config{"base_url": gw.URL}); err == nil {
			t.Error("harus error (payment_url kosong)")
		}
	})
}
