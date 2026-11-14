package pay

// ---- Xendit Invoice ----

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

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

func init() { Register(Xendit{}) }
