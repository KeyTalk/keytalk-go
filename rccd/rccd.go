// Package rccd provides implementations to work with rccd files.
package rccd

// Example
// rccd := rccd.Open(path)

import (
	"archive/zip"
	"crypto/x509"
	"io/ioutil"

	"bufio"
	"bytes"
	"fmt"
	yaml "gopkg.in/yaml.v2"
	"mime"
	"net/mail"
)

// RCCD contains the data of the parsed rccd file
type RCCD struct {
	SCA *x509.Certificate
	PCA *x509.Certificate
	UCA *x509.Certificate

	ExtraSigningCAs []*x509.Certificate

	// contains the PNG logo file
	Logo []byte

	Providers []Provider `yaml:"Providers"`

	LatestProvider string `yaml:"LatestProvider"`
	LatestService  string `yaml:"LatestService"`

	// the loglevel to use
	LogLevel string `yaml:"LogLevel"`
}

// Provider contains the supported providers
type Provider struct {
	Name           string    `yaml:"Name"`
	ContentVersion string    `yaml:"ContentVersion"`
	Server         string    `yaml:"Server"`
	Services       []Service `yaml:"Services"`
}

// Service contains the supported services
type Service struct {
	Name             string `yaml:"Name"`
	CertFormat       string `yaml:"CertFormat"`
	CertChain        bool   `yaml:"CertChain"`
	Uri              string `yaml:"Uri"`
	CertValidPercent int    `yaml:"CertValidPercent"`
	ProxySetting     string `yaml:"ProxySetting"`
	Users            []User `yaml:"Users"`
}

// User contains the supported user
type User string

type Index interface {
	Logo() string

	SCA() string
	UCA() string
	PCA() string

	ExtraSigningCAs() []string

	UserConfig() string
}

// Open will read and parse the rccd file
func Open(path string) (*RCCD, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}

	defer r.Close()

	files := map[string]*zip.File{}
	for _, f := range r.File {
		files[f.Name] = f
	}

	var index Index
	if f, ok := files["content.yaml.signed"]; ok {
		indexv1 := &IndexV1{}
		if rc, err := f.Open(); err != nil {
			return nil, err
		} else if msg, err := mail.ReadMessage(rc); err != nil {
			return nil, err
		} else if _, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type")); err != nil {
			return nil, err
		} else {
			scanner := bufio.NewScanner(msg.Body)

			parts := []*bytes.Buffer{}

			var buff *bytes.Buffer

			for scanner.Scan() {
				l := scanner.Text()
				if l == fmt.Sprintf("--%s", params["boundary"]) {
					buff = &bytes.Buffer{}
					parts = append(parts, buff)
					continue
				} else if buff == nil {
					continue
				}

				buff.Write([]byte(l))
				buff.Write([]byte("\n"))
			}

			if err := scanner.Err(); err != nil {
				return nil, err
			}

			if err := yaml.Unmarshal(parts[0].Bytes(), indexv1); err != nil {
				return nil, err
			} else {
				index = indexv1
			}
		}
	} else if f, ok := files["index.yaml"]; ok {
		indexv2 := &IndexV2{}
		if rc, err := f.Open(); err != nil {
			return nil, err
		} else if v, err := ioutil.ReadAll(rc); err != nil {
			return nil, err
		} else if err := yaml.Unmarshal(v, indexv2); err != nil {
			return nil, err
		} else {
			index = indexv2
		}
	} else {
		return nil, fmt.Errorf("No index found.")
	}

	rccd := RCCD{}

	if f, ok := files[index.Logo()]; !ok {
	} else if rc, err := f.Open(); err != nil {
	} else if v, err := ioutil.ReadAll(rc); err != nil {
	} else {
		rccd.Logo = v
	}

	if f, ok := files[index.SCA()]; !ok {
	} else if rc, err := f.Open(); err != nil {
	} else if v, err := ioutil.ReadAll(rc); err != nil {
	} else if pub, err := x509.ParseCertificates(v); err != nil {
		return nil, err
	} else {
		rccd.SCA = pub[0]
	}

	if f, ok := files[index.PCA()]; !ok {
	} else if rc, err := f.Open(); err != nil {
	} else if v, err := ioutil.ReadAll(rc); err != nil {
	} else if pub, err := x509.ParseCertificates(v); err != nil {
		return nil, err
	} else {
		rccd.PCA = pub[0]
	}

	if f, ok := files[index.UCA()]; !ok {
	} else if rc, err := f.Open(); err != nil {
	} else if v, err := ioutil.ReadAll(rc); err != nil {
	} else if pub, err := x509.ParseCertificates(v); err != nil {
		return nil, err
	} else {
		rccd.UCA = pub[0]
	}

	for _, extraSigningCA := range index.ExtraSigningCAs() {
		if f, ok := files[extraSigningCA]; !ok {
		} else if rc, err := f.Open(); err != nil {
		} else if v, err := ioutil.ReadAll(rc); err != nil {
		} else if pub, err := x509.ParseCertificates(v); err != nil {
			return nil, err
		} else {
			rccd.ExtraSigningCAs = append(rccd.ExtraSigningCAs, pub[0])
		}
	}

	if f, ok := files[index.UserConfig()]; !ok {
		return nil, fmt.Errorf("Could not find yaml in rccd %s %#v.", index.UserConfig(), index)
	} else if rc, err := f.Open(); err != nil {
	} else if v, err := ioutil.ReadAll(rc); err != nil {
		return nil, err
	} else if err := yaml.Unmarshal(v, &rccd); err != nil {
		return nil, err
	} else {
	}

	return &rccd, nil
}
