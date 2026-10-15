package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ANRCM0/TX-Node/internal/credentialprovider"
)

func main() {
	var config credentialprovider.Config
	var fingerprints string
	flag.StringVar(&config.Listen, "listen", "127.0.0.1:9443", "Provider control listen address")
	flag.StringVar(&config.StorePath, "store", "", "Absolute path to the private Provider store")
	flag.StringVar(&config.ProviderID, "provider-id", "", "Fixed Provider ID")
	flag.StringVar(&config.Epoch, "epoch", "", "Fixed positive decimal Provider instance epoch")
	flag.StringVar(&config.TLSCert, "tls-cert", "", "Operator-owned server certificate PEM")
	flag.StringVar(&config.TLSKey, "tls-key", "", "Operator-owned server private key PEM")
	flag.StringVar(&config.ClientCA, "client-ca", "", "Operator-owned trusted client CA PEM")
	flag.StringVar(&fingerprints, "client-fingerprint", "", "Comma-separated lowercase SHA-256 client leaf fingerprints")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "INVALID_ARGUMENTS")
		os.Exit(1)
	}
	config.ClientFingerprints = strings.Split(fingerprints, ",")
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := credentialprovider.Run(ctx, config, func(net.Addr) {
		fmt.Fprintln(os.Stdout, "credential_provider_listening")
	}); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
