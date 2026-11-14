package pay

// ---- Midtrans Snap ----

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

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

func init() { Register(Midtrans{}) }
