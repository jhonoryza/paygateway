package pay

// ---- iPayMu (Direct API v2) ----
// Kontrak: https://docs.ipaymu.com — signature request
// HMAC-SHA256("METHOD:VA:sha256hex(body):APIKEY", APIKey), header
// va/signature/timestamp; callback X-Signature = HMAC-SHA256(body
// ternormalisasi, secret = nomor VA).

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

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
	reqHTTP.Header.Set("signature", hmacHex(cfg["api_key"], "POST:"+cfg["va"]+":"+sha256Hex(payload)+":"+cfg["api_key"]))
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

func init() { Register(IPayMu{}) }
