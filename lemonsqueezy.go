package pay

// ---- Lemon Squeezy ----

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
)

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

func init() { Register(LemonSqueezy{}) }
