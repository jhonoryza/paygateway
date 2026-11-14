package pay

// ---- Polar ----
// Kontrak: https://polar.sh/docs — checkout POST /v1/checkouts (Bearer PAT);
// webhook svix: X-Signature "v1,<base64(HMAC-SHA256(id.timestamp.body, key))>",
// key = base64 decode dari whsec_…, event checkout.updated status succeeded.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

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

func init() { Register(Polar{}) }
