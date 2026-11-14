package pay

// ---- Sumopod Managed Payment ----
// Kontrak: https://docs.sumopod.com/guides/managed-payment/

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

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

func init() { Register(Sumopod{}) }
