package client

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"testing"
	"time"

	"github.com/kr/pretty"
)

func TestXxx(t *testing.T) {
	kc, err := New(nil, "https://pockeytalk.security-perfect.com/")
	if err != nil {
		t.Fatal("Error: %s", err.Error())
	}

	// todo(nl5887): for testing insecure skip verify
	tlsConfig := tls.Config{
		InsecureSkipVerify: true,
	}

	transport := &http.Transport{TLSClientConfig: &tlsConfig}

	kc.Client.Transport = transport

	if err := kc.hello(); err != nil {
		t.Fatal(err)
	}

	if err := kc.handshake(); err != nil {
		t.Fatal(err)
	}

	if requirements, err := kc.authenticationRequirements("hf1"); err != nil {
		t.Fatal(err)
	} else {
		_ = requirements
	}

	if err := kc.authenticate("remco@innovice-it.nl", "Remco01!", "hf1"); err != nil {
		t.Fatal(err)
	}

	if messages, err := kc.LastMessages(OptTime(time.Now().Add(time.Hour * -24))); err != nil {
		// if messages, err := kc.LastMessages(OptTime(time.Now().Add(time.Hour * -24))); err != nil {
		t.Fatal(err)
	} else {
		fmt.Printf("Last messages:\n\n%#v\n", messages)
	}

	if cert, err := kc.certificate(); err != nil {
		t.Fatal(err)
	} else {
		var tlscert tls.Certificate

		tlscert.PrivateKey = cert.PrivateKey
		tlscert.Certificate = [][]byte{
			cert.Raw,
		}

		// todo(nl5887): rootCAs from rccd?
		config := &tls.Config{
			Certificates: []tls.Certificate{tlscert},
		}

		config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			pretty.Print(clientHello)
			return nil, nil
		}

		tlsConfig.BuildNameToCertificate()

		transport := &http.Transport{TLSClientConfig: config}
		client := &http.Client{Transport: transport}

		resp, err := client.Get("https://connect.forfarmers.eu")
		if err != nil {
			fmt.Println(err.Error())
		}
		defer resp.Body.Close()

		if b, err := httputil.DumpResponse(resp, false); err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Println(string(b))
		}

	}

	if err := kc.eoc(); err != nil {
		t.Fatal(err)
	}
}
