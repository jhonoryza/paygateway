package pay

// ---- Creem ----
// Kontrak: https://docs.creem.io — checkout POST /v1/checkouts (x-api-key);
// webhook header creem-signature = HMAC-SHA256 hex body, event checkout.completed.

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
)

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

func init() { Register(Creem{}) }
