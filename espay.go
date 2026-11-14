package pay

// ---- Espay (Closed Invoice VA, merchantpg) ----
// Kontrak: https://sandbox-kit.espay.id/docs/v2/docespay/ — request form-encoded
// POST /rest/merchantpg/sendinvoice (Basic auth), signature
// SHA256(uppercase("##KEY##rq_uuid##rq_datetime##order_id##amount##ccy##comm_code##SENDINVOICE##"));
// notification dari Espay ber-signature
// SHA256(uppercase("##KEY##rq_datetime##order_id##PAYMENTREPORT##")).

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Espay struct{}

func (Espay) Name() string  { return "espay" }
func (Espay) Label() string { return "Espay" }
func (Espay) Fields() []Field {
	return []Field{
		{Key: "key", Label: "Signature Key", Secret: true},
		{Key: "password", Label: "Service Password", Secret: true},
		{Key: "comm_code", Label: "Comm Code (merchant)"},
		{Key: "environment", Label: "Environment (sandbox/production)"},
		{Key: "base_url", Label: "Override base URL (opsional)", Secret: true},
	}
}

func espaySig(key string, parts ...string) string {
	raw := "##" + key + "##" + strings.Join(parts, "##") + "##"
	sum := sha256.Sum256([]byte(strings.ToUpper(raw)))
	return hex.EncodeToString(sum[:])
}

func (Espay) CreateCharge(c Charge, cfg Config) (Result, error) {
	base := baseURL(cfg, "https://sandbox-api.espay.id", "https://api.espay.id")
	amount := fmt.Sprintf("%d.00", c.Amount)
	form := url.Values{
		"rq_uuid":     {uuidV4()},
		"rq_datetime": {time.Now().UTC().Format("2006-01-02 15:04:05")},
		"order_id":    {c.OrderID},
		"amount":      {amount},
		"ccy":         {"IDR"},
		"comm_code":   {cfg["comm_code"]},
		"remark1":     {c.Title},
		"remark2":     {c.BuyerEmail},
		"update":      {"N"},
		"va_expired":  {"24"},
		"signature":   {espaySig(cfg["key"], "SENDINVOICE", cfg["comm_code"], c.OrderID, amount, "IDR")},
	}
	// signature SENDINVOICE urutan resmi: KEY, rq_uuid, rq_datetime, order_id,
	// amount, ccy, comm_code, SENDINVOICE
	form.Set("signature", espaySig(cfg["key"],
		form.Get("rq_uuid"), form.Get("rq_datetime"), c.OrderID, amount, "IDR", cfg["comm_code"], "SENDINVOICE"))
	reqHTTP, err := http.NewRequest("POST", base+"/rest/merchantpg/sendinvoice", strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, err
	}
	reqHTTP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqHTTP.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cfg["comm_code"]+":"+cfg["password"])))
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
		ErrorCode    string `json:"error_code"`
		ErrorMessage string `json:"error_message"`
		VANumber     string `json:"va_number"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return Result{}, err
	}
	if out.ErrorCode != "0000" && out.ErrorCode != "0" {
		return Result{}, fmt.Errorf("espay menolak tagihan: %s %s", out.ErrorCode, out.ErrorMessage)
	}
	// VA tanpa halaman checkout: pay_url kosong — pembeli transfer ke va_number
	// yang tercatat di pay_ref; lunas tetap lewat payment notification.
	return Result{Ref: "VA " + out.VANumber}, nil
}

func (Espay) ParseCallback(h http.Header, body []byte, cfg Config) (Callback, error) {
	// notification form-encoded dari Espay (bukan JSON)
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return Callback{}, err
	}
	orderID := vals.Get("order_id")
	if orderID == "" {
		return Callback{}, fmt.Errorf("notification espay tanpa order_id")
	}
	if cfg["key"] == "" || vals.Get("signature") == "" {
		return Callback{}, fmt.Errorf("espay: key/signature wajib ada")
	}
	want := espaySig(cfg["key"], vals.Get("rq_datetime"), orderID, "PAYMENTREPORT")
	if subtle.ConstantTimeCompare([]byte(want), []byte(vals.Get("signature"))) != 1 {
		return Callback{}, fmt.Errorf("signature espay tidak valid")
	}
	amt, _ := strconv.ParseFloat(vals.Get("amount"), 64)
	return Callback{OrderID: orderID, Paid: true, Ref: vals.Get("payment_ref"), Amount: int(amt)}, nil
}

func init() { Register(Espay{}) }
