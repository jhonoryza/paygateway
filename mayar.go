package pay

// ---- Mayar (Payment Link) ----
// Kontrak: https://docs.mayar.id/api-reference-v2/ — payment link
// POST /hl/v2/products/payment-link/create (Bearer API key), response data.link;
// webhook event payment.received (tanpa signature terdokumentasi — optional
// secret dicek bila diisi).

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

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

func init() { Register(Mayar{}) }
