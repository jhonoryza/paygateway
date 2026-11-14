.PHONY: test cover html

# test cepat: vet + semua test
test:
	go vet ./...
	go test ./...

# test + race detector + coverage; baris terakhir = total coverage per fungsi
cover:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

# laporan coverage interaktif di browser
html:
	go tool cover -html=coverage.out
