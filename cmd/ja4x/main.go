package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/driftnet-io/go-ja4x"
)

func main() {

	raw := flag.Bool("r", false, "Output raw JA4X hash")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		log.Fatal("usage: ja4x-hash [-r] x509-cert-file")
	}

	certBytes, err := os.ReadFile(args[0])
	if err != nil {
		log.Fatal("error reading cert file", err)
	}

	// Is this PEM? Otherwise treat as a raw certificate.
	block, _ := pem.Decode(certBytes)
	if block != nil {
		certBytes = block.Bytes
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatal("failed to parse certificate", err)
	}

	if *raw {
		hash, raw := ja4x.JA4XWithRaw(cert)
		fmt.Println("ja4x:", hash)
		fmt.Println("ja4x_r:", raw)

	} else {
		fmt.Println("ja4x:", ja4x.JA4X(cert))
	}
}
