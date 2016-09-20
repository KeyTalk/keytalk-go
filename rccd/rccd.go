// Package rccd provides implementations to work with rccd files.
package rccd

// Example
// rccd := rccd.Open(path)

import (
	"archive/zip"
	"crypto/x509"
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

// RCCD contains the data of the parsed rccd file
type RCCD struct {
	SCA *x509.Certificate
	PCA *x509.Certificate
	UCA *x509.Certificate

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
	Users            []User `yaml:"users"`
}

// User contains the supported user
type User struct {
}

// Open will read and parse the rccd file
func Open(path string) (*RCCD, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}

	defer r.Close()

	rccd := RCCD{}
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}

		switch f.Name {
		case "content/SCA.der":
			if der, err := ioutil.ReadAll(rc); err != nil {
				return nil, err
			} else if pub, err := x509.ParseCertificates(der); err != nil {
				return nil, err
			} else {
				rccd.SCA = pub[0]
			}
		case "content/PCA.der":
			if der, err := ioutil.ReadAll(rc); err != nil {
				return nil, err
			} else if pub, err := x509.ParseCertificates(der); err != nil {
				return nil, err
			} else {
				rccd.PCA = pub[0]
			}
		case "content/UCA.der":
			if der, err := ioutil.ReadAll(rc); err != nil {
				return nil, err
			} else if pub, err := x509.ParseCertificates(der); err != nil {
				return nil, err
			} else {
				rccd.UCA = pub[0]
			}
		case "content/logo_v11.png":
			if v, err := ioutil.ReadAll(rc); err != nil {
				return nil, err
			} else {
				rccd.Logo = v
			}
		case "content/user.yaml":
			if v, err := ioutil.ReadAll(rc); err != nil {
				return nil, err
			} else if err := yaml.Unmarshal(v, &rccd); err != nil {
				return nil, err
			}
		case "content/SignedSvrCommPubKey.smime":
		case "content/resept_logo.bmp":
		case "content/resept_ico.bmp":
		case "content/SignedSvrCommPubKey.smime.android":
		case "content.conf.signed":
		case "content.conf.signed.android":
			// todo(nl5887): verify those
		}
	}

	return &rccd, nil
}
