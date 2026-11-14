package pay

// ---- Tripay ----

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
)

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

func init() { Register(Tripay{}) }
