package pay

// Mode simulasi bawaan (tanpa gateway nyata): CreateCharge mengembalikan hasil
// kosong tanpa memanggil gateway — cocok untuk dev/test, alur "lunas" diisi
// sendiri oleh aplikasi konsumen (deteksi via IsSimulated).

import (
	"fmt"
	"net/http"
)

type Mock struct{}

func (Mock) Name() string  { return "mock" }
func (Mock) Label() string { return "Simulasi (QRIS mock)" }
func (Mock) Fields() []Field {
	return nil
}
func (Mock) CreateCharge(Charge, Config) (Result, error) { return Result{}, nil }
func (Mock) ParseCallback(http.Header, []byte, Config) (Callback, error) {
	return Callback{}, fmt.Errorf("mode simulasi tidak punya callback")
}

func init() { Register(Mock{}) }
