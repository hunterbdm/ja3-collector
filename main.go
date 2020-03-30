package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"ja3-server/aes"
	"ja3-server/crypto/tls"
	"ja3-server/net/http"
)

var (
	cipherKey = "TMVtCVrHgP94edzjDw8jVH3g9qrPGWdD"
)

type ja3Data struct {
	Ja3       string `json:"ja3"`
	Hash      string `json:"hash"`
	UserAgent string `json:"userAgent"`
	UnixTS    int    `json:"timestamp"`
}

// ReportInternalError reports an internal error
func ReportInternalError(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(500)
	w.Write([]byte("Internal Server Error"))
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")

	hash := md5.Sum([]byte(r.JA3Fingerprint))
	out := make([]byte, 32)
	hex.Encode(out, hash[:])

	payload, err := json.Marshal(ja3Data{
		Ja3:       r.JA3Fingerprint,
		Hash:      string(out),
		UserAgent: r.Header.Get("User-Agent"),
		UnixTS:    int(time.Now().Unix()),
	})
	if err != nil {
		ReportInternalError(w, r)
		return
	}

	if r.URL.Query()["skip"] != nil && r.URL.Query()["skip"][0] == "thequeue" {
		w.WriteHeader(200)
		w.Write([]byte(payload))
	} else {
		payloadEncrypted, err := aes.Encrypt(string(payload), cipherKey)
		if err != nil {
			ReportInternalError(w, r)
			return
		}

		w.WriteHeader(200)
		w.Write([]byte(payloadEncrypted))
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Syntax: %s redis_ip:redis_port path/to/certificate.pem path/to/key.pem\n", os.Args[0])
		return
	}

	handler := http.HandlerFunc(handler)
	server := &http.Server{Addr: ":8443", Handler: handler}

	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		panic(err)
	}
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	tlsListener := tls.NewListener(ln, &tlsConfig)
	fmt.Println("HTTP up.")
	err = server.Serve(tlsListener)
	if err != nil {
		panic(err)
	}

	ln.Close()
}
