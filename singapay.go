package pay

// ---- SingaPay (Payment Link v2) ----
// Kontrak: https://docs.singapay.id/api-reference/ — OAuth B2B token
// (X-Signature HMAC-SHA512 client_id_client_secret_YYYYMMDD, secret client_secret),
// payment link POST /api/v2.0/payment-link/{account_id}; webhook
// X-Signature HMAC-SHA512("POST:endpoint:token:sha256hex(body-sorted):ts") —
// path endpoint webhook konsumen masuk ke string-to-sign, set cfg
// "callback_path" bila bukan /callback/payment.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Singapay struct{}

func (Singapay) Name() string  { return "singapay" }
func (Singapay) Label() string { return "SingaPay" }
func (Singapay) Fields() []Field {
	return []Field{
		{Key: "client_id", Label: "Client ID"},
		{Key: "client_secret", Label: "Client Secret", Secret: true},
		{Key: "partner_id", Label: "API Key (X-PARTNER-ID)"},
		{Key: "account_id", Label: "Account ID (ULID akun)"},
		{Key: "callback_path", Label: "Path webhook callback (default /callback/payment)"},
		{Key: "environment", Label: "Environment (sandbox/production)"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func hmacSha512Hex(key, msg string) string {
	m := hmac.New(sha512.New, []byte(key))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

func (Singapay) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://sandbox-payment-b2b.singapay.id", "https://payment-b2b.singapay.id")
	date := time.Now().In(time.FixedZone("WIB", 7*3600)).Format("20060102")
	sig := hmacSha512Hex(cfg["client_secret"], cfg["client_id"]+"_"+cfg["client_secret"]+"_"+date)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := postJSON("POST", base+"/api/v1.1/access-token/b2b", "",
		map[string]any{"grant_type": "client_credentials"}, &tok,
		map[string]string{
			"X-PARTNER-ID": cfg["partner_id"],
			"X-CLIENT-ID":  cfg["client_id"],
			"X-Signature":  sig,
		}); err != nil {
		return Result{}, err
	}
	if tok.AccessToken == "" {
		return Result{}, fmt.Errorf("singapay tidak mengembalikan access token")
	}
	req := map[string]any{
		"reff_no":              c.OrderID,
		"payment_link_type":    "total",
		"description":          c.Title,
		"total_amount":         c.Amount,
		"success_redirect_url": c.ReturnURL,
	}
	if c.BuyerEmail != "" {
		req["customer_email"] = c.BuyerEmail
	}
	payload, _ := json.Marshal(req)
	reqHTTP, err := http.NewRequest("POST", base+"/api/v2.0/payment-link/"+cfg["account_id"], bytes.NewReader(payload))
	if err != nil {
		return Result{}, err
	}
	reqHTTP.Header.Set("Content-Type", "application/json")
	reqHTTP.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	reqHTTP.Header.Set("X-PARTNER-ID", cfg["partner_id"])
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
		Data struct {
			PaymentURL string `json:"payment_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return Result{}, err
	}
	if out.Data.PaymentURL == "" {
		return Result{}, fmt.Errorf("singapay tidak mengembalikan payment_url: %s", truncate(b, 200))
	}
	return Result{Ref: c.OrderID, PayURL: out.Data.PaymentURL}, nil
}

func (Singapay) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	// StringToSign = POST:endpoint:token:sha256hex(body-sorted):timestamp —
	// hash body dihitung atas body asli (diteruskan apa adanya, tanpa
	// re-encoding); endpoint diambil dari cfg "callback_path" (default
	// /callback/payment).
	sig := h.Get("X-Signature")
	secret, err := failClosed(cfg, "client_secret", "X-Signature", sig, "singapay")
	if err != nil {
		return Callback{}, err
	}
	callbackPath := cfg["callback_path"]
	if callbackPath == "" {
		callbackPath = "/callback/payment"
	}
	sts := strings.Join([]string{"POST", callbackPath, h.Get("Authorization"), sha256Hex(body), h.Get("X-Timestamp")}, ":")
	if subtle.ConstantTimeCompare([]byte(hmacSha512Hex(secret, sts)), []byte(sig)) != 1 {
		return Callback{}, fmt.Errorf("signature singapay tidak valid")
	}
	var in struct {
		Event string `json:"event"`
		Data  struct {
			Transaction struct {
				ReffNo string `json:"reff_no"`
				Status string `json:"status"`
			} `json:"transaction"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Callback{}, err
	}
	if in.Event != "" && in.Event != "payment-link-transaction" {
		return Callback{Ignore: true}, nil
	}
	return Callback{OrderID: in.Data.Transaction.ReffNo, Paid: in.Data.Transaction.Status == "paid", Ref: in.Data.Transaction.ReffNo}, nil
}

func init() { Register(Singapay{}) }
