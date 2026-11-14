package pay

// Adapter gateway pembayaran. Tiap provider implement kontrak Provider;
// pemetaan field mengikuti dokumentasi API masing-masing (ujung URL bisa
// dioverride lewat cfg "base_url" untuk uji menyeluruh).

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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

func baseURL(cfg Config, sandbox, production string) string {
	if b := strings.TrimRight(cfg["base_url"], "/"); b != "" {
		return b
	}
	if cfg["environment"] == "production" {
		return production
	}
	return sandbox
}

// ---- simulasi (bawaan, tanpa gateway) ----

type Mock struct{}

func (Mock) Name() string  { return "mock" }
func (Mock) Label() string { return "Simulasi (QRIS mock)" }
func (Mock) Fields() []Field {
	return nil
}
func (Mock) CreateCharge(Charge, Config) (Result, error) { return Result{}, nil }
func (Mock) ParseCallback(http.Header, []byte, Config) (Callback, error) {
	return Callback{}, fmt.Errorf("mode simulasi tidak punya callback")
}

// ---- Midtrans Snap ----

type Midtrans struct{}

func (Midtrans) Name() string  { return "midtrans" }
func (Midtrans) Label() string { return "Midtrans Snap" }
func (Midtrans) Fields() []Field {
	return []Field{
		{Key: "server_key", Label: "Server Key", Secret: true},
		{Key: "environment", Label: "Environment (sandbox/production)"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func (Midtrans) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://app.sandbox.midtrans.com", "https://app.midtrans.com")
	req := map[string]any{
		"transaction_details": map[string]any{"order_id": c.OrderID, "gross_amount": c.Amount},
		"credit_card":         map[string]any{"secure": true},
	}
	if c.BuyerEmail != "" {
		req["customer_details"] = map[string]any{"email": c.BuyerEmail}
	}
	var out struct {
		RedirectURL string `json:"redirect_url"`
		Token       string `json:"token"`
	}
	if err := postJSON("POST", base+"/snap/v1/transactions",
		"Basic "+base64.StdEncoding.EncodeToString([]byte(cfg["server_key"]+":")),
		req, &out); err != nil {
		return Result{}, err
	}
	return Result{Ref: c.OrderID, PayURL: out.RedirectURL}, nil
}

func (Midtrans) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	var in struct {
		OrderID        string `json:"order_id"`
		StatusCode     string `json:"status_code"`
		GrossAmount    string `json:"gross_amount"`
		SignatureKey   string `json:"signature_key"`
		TransactionID  string `json:"transaction_id"`
		TransactionSts string `json:"transaction_status"`
		FraudStatus    string `json:"fraud_status"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Callback{}, err
	}
	want := sha512Hex(in.OrderID + in.StatusCode + in.GrossAmount + cfg["server_key"])
	if subtle.ConstantTimeCompare([]byte(want), []byte(in.SignatureKey)) != 1 {
		return Callback{}, fmt.Errorf("signature midtrans tidak valid")
	}
	paid := in.TransactionSts == "settlement" || in.TransactionSts == "capture"
	if paid && in.FraudStatus == "challenge" {
		paid = false
	}
	amt, _ := strconv.ParseFloat(strings.TrimSuffix(in.GrossAmount, ".00"), 64)
	return Callback{OrderID: in.OrderID, Paid: paid, Ref: in.TransactionID, Amount: int(amt)}, nil
}

// ---- Tripay ----

type Tripay struct{}

func (Tripay) Name() string  { return "tripay" }
func (Tripay) Label() string { return "Tripay" }
func (Tripay) Fields() []Field {
	return []Field{
		{Key: "api_key", Label: "API Key", Secret: true},
		{Key: "private_key", Label: "Private Key", Secret: true},
		{Key: "merchant_code", Label: "Kode Merchant"},
		{Key: "method", Label: "Metode (QRIS, BRIVA, …)"},
		{Key: "environment", Label: "Environment (sandbox/production)"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func (Tripay) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://tripay.co.id/api-sandbox", "https://tripay.co.id/api")
	method := cfg["method"]
	if method == "" {
		method = "QRIS"
	}
	sig := hmacHex(cfg["private_key"], cfg["merchant_code"]+c.OrderID+fmt.Sprint(c.Amount))
	req := map[string]any{
		"method":         method,
		"merchant_ref":   c.OrderID,
		"amount":         c.Amount,
		"customer_email": c.BuyerEmail,
		"signature":      sig,
		"callback_url":   c.CallbackURL,
		"return_url":     c.ReturnURL,
	}
	var out struct {
		Success bool `json:"success"`
		Data    struct {
			Reference   string `json:"reference"`
			CheckoutURL string `json:"checkout_url"`
		} `json:"data"`
	}
	if err := postJSON("POST", base+"/transaction/create",
		"Bearer "+cfg["api_key"], req, &out); err != nil {
		return Result{}, err
	}
	if !out.Success {
		return Result{}, fmt.Errorf("tripay menolak tagihan")
	}
	return Result{Ref: out.Data.Reference, PayURL: out.Data.CheckoutURL}, nil
}

func (Tripay) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	sig := h.Get("X-Callback-Signature")
	key, err := failClosed(cfg, "private_key", "X-Callback-Signature", sig, "tripay")
	if err != nil {
		return Callback{}, err
	}
	if subtle.ConstantTimeCompare([]byte(hmacHex(key, string(body))), []byte(sig)) != 1 {
		return Callback{}, fmt.Errorf("signature tripay tidak valid")
	}
	var in struct {
		MerchantRef string `json:"merchant_ref"`
		Reference   string `json:"reference"`
		Status      string `json:"status"`
		Amount      int    `json:"amount"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Callback{}, err
	}
	return Callback{OrderID: in.MerchantRef, Paid: in.Status == "PAID", Ref: in.Reference, Amount: in.Amount}, nil
}

// ---- Xendit Invoice ----

type Xendit struct{}

func (Xendit) Name() string  { return "xendit" }
func (Xendit) Label() string { return "Xendit Invoice" }
func (Xendit) Fields() []Field {
	return []Field{
		{Key: "api_key", Label: "API Key", Secret: true},
		{Key: "callback_token", Label: "Callback Token", Secret: true},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func (Xendit) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://api.xendit.co", "https://api.xendit.co")
	req := map[string]any{
		"external_id": c.OrderID,
		"amount":      c.Amount,
		"description": c.Title,
	}
	if c.BuyerEmail != "" {
		req["customer"] = map[string]any{"email": c.BuyerEmail}
	}
	if c.ReturnURL != "" {
		req["success_redirect_url"] = c.ReturnURL
	}
	var out struct {
		ID         string `json:"id"`
		InvoiceURL string `json:"invoice_url"`
	}
	if err := postJSON("POST", base+"/v2/invoices",
		"Basic "+base64.StdEncoding.EncodeToString([]byte(cfg["api_key"]+":")),
		req, &out); err != nil {
		return Result{}, err
	}
	return Result{Ref: out.ID, PayURL: out.InvoiceURL}, nil
}

func (Xendit) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	tok, err := failClosed(cfg, "callback_token", "X-Callback-Token", h.Get("X-Callback-Token"), "xendit")
	if err != nil {
		return Callback{}, err
	}
	if subtle.ConstantTimeCompare([]byte(h.Get("X-Callback-Token")), []byte(tok)) != 1 {
		return Callback{}, fmt.Errorf("callback token xendit tidak valid")
	}
	var in struct {
		ExternalID string `json:"external_id"`
		ID         string `json:"id"`
		Status     string `json:"status"`
		Amount     int    `json:"amount"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Callback{}, err
	}
	paid := in.Status == "PAID" || in.Status == "SETTLED"
	return Callback{OrderID: in.ExternalID, Paid: paid, Ref: in.ID, Amount: in.Amount}, nil
}

// ---- Lemon Squeezy ----

type LemonSqueezy struct{}

func (LemonSqueezy) Name() string  { return "lemonsqueezy" }
func (LemonSqueezy) Label() string { return "Lemon Squeezy" }
func (LemonSqueezy) Fields() []Field {
	return []Field{
		{Key: "api_key", Label: "API Key", Secret: true},
		{Key: "signing_secret", Label: "Signing Secret (webhook)", Secret: true},
		{Key: "store_id", Label: "Store ID"},
		{Key: "variant_id", Label: "Variant ID produk jasa layanan checkout"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func (LemonSqueezy) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://api.lemonsqueezy.com", "https://api.lemonsqueezy.com")
	req := map[string]any{
		"data": map[string]any{
			"type": "checkouts",
			"attributes": map[string]any{
				"custom_price": true,
				"product_options": map[string]any{
					"name":        c.Title,
					"description": "Order #" + c.OrderID,
				},
				"checkout_data": map[string]any{"email": c.BuyerEmail, "custom": map[string]any{"order_id": c.OrderID}},
			},
			"relationships": map[string]any{
				"store":   map[string]any{"data": map[string]any{"type": "stores", "id": cfg["store_id"]}},
				"variant": map[string]any{"data": map[string]any{"type": "variants", "id": cfg["variant_id"]}},
			},
		},
	}
	var out struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				URL string `json:"url"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := postJSON("POST", base+"/v1/checkouts",
		"Bearer "+cfg["api_key"], req, &out); err != nil {
		return Result{}, err
	}
	return Result{Ref: out.Data.ID, PayURL: out.Data.Attributes.URL}, nil
}

func (LemonSqueezy) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	sig := h.Get("X-Signature")
	secret, err := failClosed(cfg, "signing_secret", "X-Signature", sig, "lemonsqueezy")
	if err != nil {
		return Callback{}, err
	}
	if subtle.ConstantTimeCompare([]byte(hmacHex(secret, string(body))), []byte(sig)) != 1 {
		return Callback{}, fmt.Errorf("signature lemonsqueezy tidak valid")
	}
	var in struct {
		Meta struct {
			EventName  string `json:"event_name"`
			CustomData struct {
				OrderID string `json:"order_id"`
			} `json:"custom_data"`
		} `json:"meta"`
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Callback{}, err
	}
	if in.Meta.EventName != "order_created" && in.Meta.EventName != "order_paid" {
		return Callback{Ignore: true}, nil
	}
	return Callback{OrderID: in.Meta.CustomData.OrderID, Paid: true, Ref: in.Data.ID}, nil
}

// ---- DOKU (Checkout API v2.1) ----

type Doku struct{}

func (Doku) Name() string  { return "doku" }
func (Doku) Label() string { return "DOKU" }
func (Doku) Fields() []Field {
	return []Field{
		{Key: "client_id", Label: "Client ID"},
		{Key: "secret_key", Label: "Secret Key", Secret: true},
		{Key: "callback_token", Label: "Callback Token (wajib untuk callback)", Secret: true},
		{Key: "environment", Label: "Environment (sandbox/production)"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func (Doku) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://api.sandbox.doku.com", "https://api.doku.com")
	req := map[string]any{
		"order":    map[string]any{"amount": c.Amount, "invoice_number": c.OrderID},
		"payment":  map[string]any{"payment_due_to_delta": 60},
		"customer": map[string]any{"email": c.BuyerEmail},
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return Result{}, err
	}
	reqID := uuidV4()
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	m := hmac.New(sha256.New, []byte(cfg["secret_key"]))
	fmt.Fprintf(m, "%s%s%s%s", cfg["client_id"], reqID, ts, payload)
	auth := base64.StdEncoding.EncodeToString(m.Sum(nil))

	reqHTTP, err := http.NewRequest("POST", base+"/orders/v2.1/order", bytes.NewReader(payload))
	if err != nil {
		return Result{}, err
	}
	reqHTTP.Header.Set("Content-Type", "application/json")
	reqHTTP.Header.Set("Client-Id", cfg["client_id"])
	reqHTTP.Header.Set("Request-Id", reqID)
	reqHTTP.Header.Set("Request-Timestamp", ts)
	reqHTTP.Header.Set("Signature", auth)
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(reqHTTP)
	if err != nil {
		return Result{}, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 400 {
		return Result{}, fmt.Errorf("gateway %s: %s", res.Status, truncate(b, 200))
	}
	var out struct {
		Order struct {
			InvoiceNumber string `json:"invoice_number"`
		} `json:"order"`
		Response struct {
			Payment struct {
				URL string `json:"url"`
			} `json:"payment"`
		} `json:"response"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return Result{}, err
	}
	return Result{Ref: out.Order.InvoiceNumber, PayURL: out.Response.Payment.URL}, nil
}

func (Doku) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	tok, err := failClosed(cfg, "callback_token", "X-Callback-Token", h.Get("X-Callback-Token"), "doku")
	if err != nil {
		return Callback{}, err
	}
	if subtle.ConstantTimeCompare([]byte(h.Get("X-Callback-Token")), []byte(tok)) != 1 {
		return Callback{}, fmt.Errorf("callback token doku tidak valid")
	}
	var in struct {
		Order struct {
			InvoiceNumber string `json:"invoice_number"`
			Amount        int    `json:"amount"`
		} `json:"order"`
		Transaction struct {
			Status    string `json:"status"`
			Reference string `json:"reference"`
		} `json:"transaction"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Callback{}, err
	}
	return Callback{OrderID: in.Order.InvoiceNumber, Paid: in.Transaction.Status == "SUCCESS", Ref: in.Transaction.Reference, Amount: in.Order.Amount}, nil
}

// ---- Sumopod Managed Payment ----
// Kontrak: https://docs.sumopod.com/guides/managed-payment/

type Sumopod struct{}

func (Sumopod) Name() string  { return "sumopod" }
func (Sumopod) Label() string { return "Sumopod Managed Payment" }
func (Sumopod) Fields() []Field {
	return []Field{
		{Key: "api_key", Label: "API Key (X-Api-Key)", Secret: true},
		{Key: "webhook_token", Label: "Webhook Token (whtok_…)", Secret: true},
		{Key: "payment_method_type_code", Label: "Metode bayar (QRIS, …)"},
		{Key: "environment", Label: "Environment (sandbox/production)"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func (Sumopod) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://api-pay-sandbox.sumopod.com", "https://api-pay.sumopod.com")
	method := cfg["payment_method_type_code"]
	if method == "" {
		method = "QRIS"
	}
	req := map[string]any{
		"order_id":                 c.OrderID,
		"amount":                   c.Amount,
		"currency":                 "IDR",
		"payment_method_type_code": method,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return Result{}, err
	}
	reqHTTP, err := http.NewRequest("POST", base+"/api/v1/payments", bytes.NewReader(payload))
	if err != nil {
		return Result{}, err
	}
	reqHTTP.Header.Set("Content-Type", "application/json")
	reqHTTP.Header.Set("X-Api-Key", cfg["api_key"])
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(reqHTTP)
	if err != nil {
		return Result{}, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 400 {
		return Result{}, fmt.Errorf("gateway %s: %s", res.Status, truncate(b, 200))
	}
	var out struct {
		PaymentLinkURL string `json:"payment_link_url"`
		PaymentCode    string `json:"payment_code"`
		Data           struct {
			PaymentLinkURL string `json:"payment_link_url"`
			PaymentCode    string `json:"payment_code"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return Result{}, err
	}
	if out.Data.PaymentLinkURL != "" {
		out.PaymentLinkURL = out.Data.PaymentLinkURL
	}
	if out.PaymentLinkURL == "" {
		return Result{}, fmt.Errorf("sumopod tidak mengembalikan payment_link_url: %s", truncate(b, 200))
	}
	return Result{Ref: firstNonEmpty(out.PaymentCode, c.OrderID), PayURL: out.PaymentLinkURL}, nil
}

func (Sumopod) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	tok, err := failClosed(cfg, "webhook_token", "X-Webhook-Token", h.Get("X-Webhook-Token"), "sumopod")
	if err != nil {
		return Callback{}, err
	}
	if subtle.ConstantTimeCompare([]byte(h.Get("X-Webhook-Token")), []byte(tok)) != 1 {
		return Callback{}, fmt.Errorf("webhook token sumopod tidak valid")
	}
	// payload nyata: {"event_type":"payment.completed","data":{payment_id, order_id, status, ...}}
	// (contoh flat di docs tidak sesuai kiriman aktual — baca kedua bentuk)
	var in struct {
		EventType string `json:"event_type"`
		Event     string `json:"event"`
		Type      string `json:"type"`
		Data      struct {
			PaymentID string `json:"payment_id"`
			OrderID   string `json:"order_id"`
			Status    string `json:"status"`
			Amount    any    `json:"amount"` // gateway kirim angka atau string
		} `json:"data"`
		PaymentID string `json:"payment_id"`
		OrderID   string `json:"order_id"`
		Status    string `json:"status"`
		Amount    any    `json:"amount"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Callback{}, err
	}
	event := h.Get("svix-event-type")
	if event == "" {
		event = firstNonEmpty(in.EventType, in.Event, in.Type)
	}
	status := firstNonEmpty(in.Data.Status, in.Status)
	orderID := firstNonEmpty(in.Data.OrderID, in.OrderID)
	paymentID := firstNonEmpty(in.Data.PaymentID, in.PaymentID)
	if event != "" && event != "payment.completed" {
		return Callback{Ignore: true}, nil
	}
	paid := status == "completed" || status == "paid" || event == "payment.completed"
	amt := anyAmount(in.Data.Amount)
	if amt == 0 {
		amt = anyAmount(in.Amount)
	}
	return Callback{OrderID: orderID, Paid: paid, Ref: paymentID, Amount: amt}, nil
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

// ---- iPayMu (Direct API v2) ----
// Kontrak: https://docs.ipaymu.com — signature request
// HMAC-SHA256("METHOD:VA:sha256hex(body):APIKEY", APIKey), header
// va/signature/timestamp; callback X-Signature = HMAC-SHA256(body
// ternormalisasi, secret = nomor VA).

type IPayMu struct{}

func (IPayMu) Name() string  { return "ipaymu" }
func (IPayMu) Label() string { return "iPayMu" }
func (IPayMu) Fields() []Field {
	return []Field{
		{Key: "api_key", Label: "API Key", Secret: true},
		{Key: "va", Label: "Nomor VA (merchant)", Secret: true},
		{Key: "environment", Label: "Environment (sandbox/production)"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func (IPayMu) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://sandbox.ipaymu.com", "https://ipaymu.com")
	req := map[string]any{
		"product":     []string{c.Title},
		"qty":         []string{"1"},
		"price":       []string{fmt.Sprint(c.Amount)},
		"notifyUrl":   c.CallbackURL,
		"returnUrl":   c.ReturnURL,
		"cancelUrl":   c.ReturnURL,
		"referenceId": c.OrderID,
	}
	if c.BuyerEmail != "" {
		req["buyerEmail"] = c.BuyerEmail
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return Result{}, err
	}
	ts := time.Now().UTC().Format("20060102150405")
	// body harus dikirim persis seperti string yang di-hash (urutan key sama)
	reqHTTP, err := http.NewRequest("POST", base+"/api/v2/payment", bytes.NewReader(payload))
	if err != nil {
		return Result{}, err
	}
	reqHTTP.Header.Set("Content-Type", "application/json")
	reqHTTP.Header.Set("va", cfg["va"])
	reqHTTP.Header.Set("timestamp", ts)
	reqHTTP.Header.Set("signature", hmacHex(cfg["api_key"], "POST:"+cfg["va"]+":"+sha512Hex2(payload)+":"+cfg["api_key"]))
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(reqHTTP)
	if err != nil {
		return Result{}, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 400 {
		return Result{}, fmt.Errorf("gateway %s: %s", res.Status, truncate(b, 200))
	}
	var out struct {
		Status int `json:"Status"`
		Data   struct {
			URL         string `json:"Url"`
			Transaction string `json:"TransactionId"`
		} `json:"Data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return Result{}, err
	}
	if out.Data.URL == "" {
		return Result{}, fmt.Errorf("ipaymu tidak mengembalikan url: %s", truncate(b, 200))
	}
	return Result{Ref: firstNonEmpty(out.Data.Transaction, c.OrderID), PayURL: out.Data.URL}, nil
}

func (IPayMu) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
		// signature = HMAC-SHA256(body JSON ternormalisasi, secret = nomor VA).
		// Normalisasi resmi: sort key, buang "signature", tipa angka/boolean, escape
		// "/". Adapter ini memverifikasi HMAC atas body mentah apa adanya — bekerja
		// karena callback iPayMu ber-field flat sehingga normalisasi = asli.
		sig := h.Get("X-Signature")
	va, err := failClosed(cfg, "va", "X-Signature", sig, "ipaymu")
	if err != nil {
		return Callback{}, err
	}
	if subtle.ConstantTimeCompare([]byte(hmacHex(va, string(body))), []byte(sig)) != 1 {
		return Callback{}, fmt.Errorf("signature ipaymu tidak valid")
	}
	var in struct {
		ReferenceID string `json:"referenceId"`
		Reference   string `json:"reference_id"`
		SID         string `json:"sid"`
		TrxID       any    `json:"trx_id"` // dokumentasi: Integer, tapi terima juga string
		StatusCode  int    `json:"status_code"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Callback{}, err
	}
	trxID := ""
	switch v := in.TrxID.(type) {
	case string:
		trxID = v
	case float64:
		trxID = fmt.Sprint(int64(v))
	}
	orderID := firstNonEmpty(in.ReferenceID, in.Reference, in.SID)
	return Callback{OrderID: orderID, Paid: in.StatusCode == 1, Ref: trxID}, nil
}

// sha5122: SHA-256 hex dari payload (nama dibedakan dari sha512Hex bawaan).
func sha512Hex2(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ---- Espay (Closed Invoice VA, merchantpg) ----
// Kontrak: https://sandbox-kit.espay.id/docs/v2/docespay/ — request form-encoded
// POST /rest/merchantpg/sendinvoice (Basic auth), signature
// SHA256(uppercase("##KEY##rq_uuid##rq_datetime##order_id##amount##ccy##comm_code##SENDINVOICE##"));
// notification dari Espay ber-signature
// SHA256(uppercase("##KEY##rq_datetime##order_id##PAYMENTREPORT##")).

type Espay struct{}

func (Espay) Name() string  { return "espay" }
func (Espay) Label() string { return "Espay" }
func (Espay) Fields() []Field {
	return []Field{
		{Key: "key", Label: "Signature Key", Secret: true},
		{Key: "password", Label: "Service Password", Secret: true},
		{Key: "comm_code", Label: "Comm Code (merchant)"},
		{Key: "environment", Label: "Environment (sandbox/production)"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func espaySig(key string, parts ...string) string {
	raw := "##" + key + "##" + strings.Join(parts, "##") + "##"
	sum := sha256.Sum256([]byte(strings.ToUpper(raw)))
	return hex.EncodeToString(sum[:])
}

func (Espay) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://sandbox-api.espay.id", "https://api.espay.id")
	amount := fmt.Sprintf("%d.00", c.Amount)
	form := url.Values{
		"rq_uuid":     {uuidV4()},
		"rq_datetime": {time.Now().UTC().Format("2006-01-02 15:04:05")},
		"order_id":    {c.OrderID},
		"amount":      {amount},
		"ccy":         {"IDR"},
		"comm_code":   {cfg["comm_code"]},
		"remark1":     {c.Title},
		"remark2":     {c.BuyerEmail},
		"update":      {"N"},
		"va_expired":  {"24"},
		"signature":   {espaySig(cfg["key"], "SENDINVOICE", cfg["comm_code"], c.OrderID, amount, "IDR")},
	}
	// signature SENDINVOICE urutan resmi: KEY, rq_uuid, rq_datetime, order_id,
	// amount, ccy, comm_code, SENDINVOICE
	form.Set("signature", espaySig(cfg["key"],
		form.Get("rq_uuid"), form.Get("rq_datetime"), c.OrderID, amount, "IDR", cfg["comm_code"], "SENDINVOICE"))
	reqHTTP, err := http.NewRequest("POST", base+"/rest/merchantpg/sendinvoice", strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, err
	}
	reqHTTP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqHTTP.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cfg["comm_code"]+":"+cfg["password"])))
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(reqHTTP)
	if err != nil {
		return Result{}, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 400 {
		return Result{}, fmt.Errorf("gateway %s: %s", res.Status, truncate(b, 200))
	}
	var out struct {
		ErrorCode    string `json:"error_code"`
		ErrorMessage string `json:"error_message"`
		VANumber     string `json:"va_number"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return Result{}, err
	}
	if out.ErrorCode != "0000" && out.ErrorCode != "0" {
		return Result{}, fmt.Errorf("espay menolak tagihan: %s %s", out.ErrorCode, out.ErrorMessage)
	}
	// VA tanpa halaman checkout: pay_url kosong — pembeli transfer ke va_number
	// yang tercatat di pay_ref; lunas tetap lewat payment notification.
	return Result{Ref: "VA " + out.VANumber}, nil
}

func (Espay) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	// notification form-encoded dari Espay (bukan JSON)
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return Callback{}, err
	}
	orderID := vals.Get("order_id")
	if orderID == "" {
		return Callback{}, fmt.Errorf("notification espay tanpa order_id")
	}
	if cfg["key"] == "" || vals.Get("signature") == "" {
		return Callback{}, fmt.Errorf("espay: key/signature wajib ada")
	}
	want := espaySig(cfg["key"], vals.Get("rq_datetime"), orderID, "PAYMENTREPORT")
	if subtle.ConstantTimeCompare([]byte(want), []byte(vals.Get("signature"))) != 1 {
		return Callback{}, fmt.Errorf("signature espay tidak valid")
	}
	amt, _ := strconv.ParseFloat(vals.Get("amount"), 64)
	return Callback{OrderID: orderID, Paid: true, Ref: vals.Get("payment_ref"), Amount: int(amt)}, nil
}

// ---- SingaPay (Payment Link v2) ----
// Kontrak: https://docs.singapay.id/api-reference/ — OAuth B2B token
// (X-Signature HMAC-SHA512 client_id_client_secret_YYYYMMDD, secret client_secret),
// payment link POST /api/v2.0/payment-link/{account_id}; webhook
// X-Signature HMAC-SHA512("POST:endpoint:token:sha256hex(body-sorted):ts") —
// path endpoint webhook konsumen masuk ke string-to-sign, set cfg
// "callback_path" bila bukan /callback/payment.

type Singapay struct{}

func (Singapay) Name() string  { return "singapay" }
func (Singapay) Label() string { return "SingaPay" }
func (Singapay) Fields() []Field {
	return []Field{
		{Key: "client_id", Label: "Client ID"},
		{Key: "client_secret", Label: "Client Secret", Secret: true},
		{Key: "partner_id", Label: "API Key (X-PARTNER-ID)"},
		{Key: "account_id", Label: "Account ID (ULID akun)"},
		{Key: "callback_path", Label: "Path webhook callback (default /callback/payment)"},
		{Key: "environment", Label: "Environment (sandbox/production)"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func hmacSha512Hex(key, msg string) string {
	m := hmac.New(sha512.New, []byte(key))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

func (Singapay) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://sandbox-payment-b2b.singapay.id", "https://payment-b2b.singapay.id")
	date := time.Now().In(time.FixedZone("WIB", 7*3600)).Format("20060102")
	sig := hmacSha512Hex(cfg["client_secret"], cfg["client_id"]+"_"+cfg["client_secret"]+"_"+date)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := postJSON("POST", base+"/api/v1.1/access-token/b2b", "",
		map[string]any{"grant_type": "client_credentials"}, &tok,
		map[string]string{
			"X-PARTNER-ID": cfg["partner_id"],
			"X-CLIENT-ID":  cfg["client_id"],
			"X-Signature":  sig,
		}); err != nil {
		return Result{}, err
	}
	if tok.AccessToken == "" {
		return Result{}, fmt.Errorf("singapay tidak mengembalikan access token")
	}
	req := map[string]any{
		"reff_no":              c.OrderID,
		"payment_link_type":    "total",
		"description":          c.Title,
		"total_amount":         c.Amount,
		"success_redirect_url": c.ReturnURL,
	}
	if c.BuyerEmail != "" {
		req["customer_email"] = c.BuyerEmail
	}
	payload, _ := json.Marshal(req)
	reqHTTP, err := http.NewRequest("POST", base+"/api/v2.0/payment-link/"+cfg["account_id"], bytes.NewReader(payload))
	if err != nil {
		return Result{}, err
	}
	reqHTTP.Header.Set("Content-Type", "application/json")
	reqHTTP.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	reqHTTP.Header.Set("X-PARTNER-ID", cfg["partner_id"])
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(reqHTTP)
	if err != nil {
		return Result{}, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 400 {
		return Result{}, fmt.Errorf("gateway %s: %s", res.Status, truncate(b, 200))
	}
	var out struct {
		Data struct {
			PaymentURL string `json:"payment_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return Result{}, err
	}
	if out.Data.PaymentURL == "" {
		return Result{}, fmt.Errorf("singapay tidak mengembalikan payment_url: %s", truncate(b, 200))
	}
	return Result{Ref: c.OrderID, PayURL: out.Data.PaymentURL}, nil
}

func (Singapay) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	// StringToSign = POST:endpoint:token:sha256hex(body-sorted):timestamp —
	// hash body dihitung atas body asli (diteruskan apa adanya, tanpa
	// re-encoding); endpoint diambil dari cfg "callback_path" (default
	// /callback/payment).
	sig := h.Get("X-Signature")
	secret, err := failClosed(cfg, "client_secret", "X-Signature", sig, "singapay")
	if err != nil {
		return Callback{}, err
	}
	callbackPath := cfg["callback_path"]
	if callbackPath == "" {
		callbackPath = "/callback/payment"
	}
	sts := strings.Join([]string{"POST", callbackPath, h.Get("Authorization"), sha512Hex2(body), h.Get("X-Timestamp")}, ":")
	if subtle.ConstantTimeCompare([]byte(hmacSha512Hex(secret, sts)), []byte(sig)) != 1 {
		return Callback{}, fmt.Errorf("signature singapay tidak valid")
	}
	var in struct {
		Event string `json:"event"`
		Data  struct {
			Transaction struct {
				ReffNo string `json:"reff_no"`
				Status string `json:"status"`
			} `json:"transaction"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Callback{}, err
	}
	if in.Event != "" && in.Event != "payment-link-transaction" {
		return Callback{Ignore: true}, nil
	}
	return Callback{OrderID: in.Data.Transaction.ReffNo, Paid: in.Data.Transaction.Status == "paid", Ref: in.Data.Transaction.ReffNo}, nil
}

// ---- Mayar (Payment Link) ----
// Kontrak: https://docs.mayar.id/api-reference-v2/ — payment link
// POST /hl/v2/products/payment-link/create (Bearer API key), response data.link;
// webhook event payment.received (tanpa signature terdokumentasi — optional
// secret dicek bila diisi).

type Mayar struct{}

func (Mayar) Name() string  { return "mayar" }
func (Mayar) Label() string { return "Mayar" }
func (Mayar) Fields() []Field {
	return []Field{
		{Key: "api_key", Label: "API Key", Secret: true},
		{Key: "webhook_secret", Label: "Secret webhook (wajib untuk callback)", Secret: true},
		{Key: "environment", Label: "Environment (sandbox=mayar.io/production=mayar.id)"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func (Mayar) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://api.mayar.io", "https://api.mayar.id")
	req := map[string]any{
		"name":        c.Title + " #" + c.OrderID,
		"amount":      c.Amount,
		"description": "Order #" + c.OrderID,
		"redirectUrl": c.ReturnURL,
	}
	var out struct {
		Data struct {
			ID   string `json:"id"`
			Link string `json:"link"`
		} `json:"data"`
	}
	if err := postJSON("POST", base+"/hl/v2/products/payment-link/create",
		"Bearer "+cfg["api_key"], req, &out); err != nil {
		return Result{}, err
	}
	if out.Data.Link == "" {
		return Result{}, fmt.Errorf("mayar tidak mengembalikan link")
	}
	return Result{Ref: firstNonEmpty(out.Data.ID, c.OrderID), PayURL: out.Data.Link}, nil
}

func (Mayar) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	sig := h.Get("X-Signature")
	sec, err := failClosed(cfg, "webhook_secret", "X-Signature", sig, "mayar")
	if err != nil {
		return Callback{}, err
	}
	if subtle.ConstantTimeCompare([]byte(hmacHex(sec, string(body))), []byte(sig)) != 1 {
		return Callback{}, fmt.Errorf("signature mayar tidak valid")
	}
	var in struct {
		Event string `json:"event"`
		Data  struct {
			ProductName string `json:"productName"`
			Description string `json:"description"`
			ID          string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Callback{}, err
	}
	if in.Event != "" && in.Event != "payment.received" {
		return Callback{Ignore: true}, nil
	}
	// payload mayar tidak memuat order id konsumen — order id disimpan di
	// description ("Order #<id>") saat membuat payment link
	orderID := ""
	if i := strings.LastIndex(in.Data.Description, "Order #"); i >= 0 {
		orderID = strings.TrimSpace(in.Data.Description[i+len("Order #"):])
	}
	return Callback{OrderID: orderID, Paid: true, Ref: in.Data.ID}, nil
}

// ---- Creem ----
// Kontrak: https://docs.creem.io — checkout POST /v1/checkouts (x-api-key);
// webhook header creem-signature = HMAC-SHA256 hex body, event checkout.completed.

type Creem struct{}

func (Creem) Name() string  { return "creem" }
func (Creem) Label() string { return "Creem" }
func (Creem) Fields() []Field {
	return []Field{
		{Key: "api_key", Label: "API Key", Secret: true},
		{Key: "webhook_secret", Label: "Webhook Secret", Secret: true},
		{Key: "product_id", Label: "Product ID (prod_…)"},
		{Key: "environment", Label: "Environment (sandbox/production)"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func (Creem) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://test-api.creem.io", "https://api.creem.io")
	req := map[string]any{
		"product_id":  cfg["product_id"],
		"success_url": c.ReturnURL,
		"metadata":    map[string]any{"order_id": c.OrderID},
	}
	if c.BuyerEmail != "" {
		req["customer"] = map[string]any{"email": c.BuyerEmail}
	}
	var out struct {
		ID          string `json:"id"`
		CheckoutURL string `json:"checkout_url"`
	}
	if err := postJSON("POST", base+"/v1/checkouts", "",
		req, &out, map[string]string{"x-api-key": cfg["api_key"]}); err != nil {
		return Result{}, err
	}
	return Result{Ref: out.ID, PayURL: out.CheckoutURL}, nil
}

func (Creem) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	sig := h.Get("creem-signature")
	secret, err := failClosed(cfg, "webhook_secret", "creem-signature", sig, "creem")
	if err != nil {
		return Callback{}, err
	}
	if subtle.ConstantTimeCompare([]byte(hmacHex(secret, string(body))), []byte(sig)) != 1 {
		return Callback{}, fmt.Errorf("signature creem tidak valid")
	}
	var in struct {
		EventType string `json:"eventType"`
		Object    struct {
			ID       string            `json:"id"`
			Metadata map[string]string `json:"metadata"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Callback{}, err
	}
	if in.EventType != "checkout.completed" {
		return Callback{Ignore: true}, nil
	}
	return Callback{OrderID: in.Object.Metadata["order_id"], Paid: true, Ref: in.Object.ID}, nil
}

// ---- Polar ----
// Kontrak: https://polar.sh/docs — checkout POST /v1/checkouts (Bearer PAT);
// webhook svix: X-Signature "v1,<base64(HMAC-SHA256(id.timestamp.body, key))>",
// key = base64 decode dari whsec_…, event checkout.updated status succeeded.

type Polar struct{}

func (Polar) Name() string  { return "polar" }
func (Polar) Label() string { return "Polar" }
func (Polar) Fields() []Field {
	return []Field{
		{Key: "api_key", Label: "Access Token (polar_…)", Secret: true},
		{Key: "webhook_secret", Label: "Webhook Secret (whsec_…)", Secret: true},
		{Key: "product_id", Label: "Product ID (UUID)"},
		{Key: "environment", Label: "Environment (sandbox/production)"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func (Polar) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://sandbox-api.polar.sh", "https://api.polar.sh")
	req := map[string]any{
		"products":       []string{cfg["product_id"]},
		"amount":         c.Amount,
		"currency":       "idr",
		"metadata":       map[string]any{"order_id": c.OrderID},
		"success_url":    c.ReturnURL,
		"customer_email": c.BuyerEmail,
	}
	var out struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := postJSON("POST", base+"/v1/checkouts", "Bearer "+cfg["api_key"], req, &out); err != nil {
		return Result{}, err
	}
	return Result{Ref: out.ID, PayURL: out.URL}, nil
}

func (Polar) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	sig := h.Get("webhook-signature")
	secretRaw, err := failClosed(cfg, "webhook_secret", "webhook-signature", sig, "polar")
	if err != nil {
		return Callback{}, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secretRaw, "whsec_"))
	if err != nil {
		return Callback{}, fmt.Errorf("secret polar tidak valid: %w", err)
	}
	signed := h.Get("webhook-id") + "." + h.Get("webhook-timestamp") + "." + string(body)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(signed))
	want := "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(want), []byte(sig)) != 1 {
		return Callback{}, fmt.Errorf("signature polar tidak valid")
	}
	var in struct {
		Type string `json:"type"`
		Data struct {
			ID       string            `json:"id"`
			Status   string            `json:"status"`
			Metadata map[string]string `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Callback{}, err
	}
	if in.Type != "checkout.updated" {
		return Callback{Ignore: true}, nil
	}
	return Callback{OrderID: in.Data.Metadata["order_id"], Paid: in.Data.Status == "succeeded", Ref: in.Data.ID}, nil
}

func uuidV4() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func init() {
	Register(Mock{})
	Register(Midtrans{})
	Register(Doku{})
	Register(LemonSqueezy{})
	Register(Tripay{})
	Register(Xendit{})
	Register(Sumopod{})
	Register(IPayMu{})
	Register(Espay{})
	Register(Singapay{})
	Register(Mayar{})
	Register(Creem{})
	Register(Polar{})
}
