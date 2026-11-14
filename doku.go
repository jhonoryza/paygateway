package pay

// ---- DOKU (Checkout API v2.1) ----

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

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

func init() { Register(Doku{}) }
