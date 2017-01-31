// Package client provides the Keytalk client
package client

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/keytalk/keytalk-go/hwsig"
	"github.com/keytalk/keytalk-go/rccd"
	"github.com/op/go-logging"

	"golang.org/x/crypto/pkcs12"
)

var log = logging.MustGetLogger("keytalk-go:client")

// Client is the Keytalk Client
type Client struct {
	Client *http.Client

	BaseURL *url.URL

	rccd *rccd.RCCD
}

// NewRequest will create a new Keytalk request
func (c *Client) NewRequest(action string, values url.Values) (*http.Request, error) {
	u, err := url.Parse(fmt.Sprintf("%s/%s/%s", RCDPV2_HTTP_REQUEST_URI_PREFIX, RCDP_VERSION_2_0, action))
	if err != nil {
		return nil, err
	}

	u.RawQuery = values.Encode()

	url := c.BaseURL.ResolveReference(u)
	req, err := http.NewRequest("POST", url.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("User-Agent", fmt.Sprintf("%s/%s", "keytalk-go", "1.0"))
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Accept", "application/json")

	return req, nil
}

// New will return a Keytalk Client
func New(rccd *rccd.RCCD, u string) (*Client, error) {
	baseURL, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	kc := Client{
		Client:  http.DefaultClient,
		BaseURL: baseURL,
		rccd:    rccd,
	}

	jar, _ := cookiejar.New(nil)
	kc.Client.Jar = jar
	return &kc, nil
}

// Do will execute the Keytalk request
func (wd *Client) Do(req *http.Request, v interface{}) error {
	if b, err := httputil.DumpRequest(req, true); err == nil {
		log.Debugf("Request: %s\n", string(b))
	}

	resp, err := wd.Client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if b, err := httputil.DumpResponse(resp, true); err == nil {
		log.Debugf("Response: %s\n", string(b))
	}

	var r io.Reader = resp.Body

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < 300 {
	} else if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("Not found")
	} else {
		return fmt.Errorf("Unexpected status code: %d", resp.StatusCode)
	}

	if v == nil {
		return nil
	} else if err := json.NewDecoder(r).Decode(v); err != nil {
		return err
	}

	return nil
}

type helloResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

type handshakeResponse struct {
	Status string `json:"status"`
}

type authRequirementsResponse struct {
	Status          string   `json:"status"`
	CredentialTypes []string `json:"credential-types"`
	Formula         string   `json:"hwsig_formula"`
	Prompt          string   `json:"password-prompt"`
	ServiceURIs     []string `json:"service-uris"`
}

type authenticateResponse struct {
	Status           string      `json:"status"`
	AuthStatus       string      `json:"auth-status"`
	Delay            string      `json:"delay"`
	PasswordValidity string      `json:"password-validity"`
	CredentialTypes  []string    `json:"credential-types"`
	Formula          string      `json:"hwsig_formula"`
	Prompt           string      `json:"password-prompt"`
	Challenges       []Challenge `json:"challenges"`
}

type Challenge struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type lastMessagesResponse struct {
	Status      string          `json:"status"`
	RawMessages json.RawMessage `json:"messages"`
}

type Message struct {
	Text string `json:"text"`
	Date Time   `json:"utc"`
}

type Time struct {
	time.Time
}

func (t *Time) UnmarshalJSON(b []byte) (err error) {
	if b[0] == '"' && b[len(b)-1] == '"' {
		b = b[1 : len(b)-1]
	}

	t.Time, err = time.Parse("2006-01-02T15:04:05-0700", string(b))
	return
}

type getCertificateResponse struct {
	Status string `json:"status"`
	Cert   string `json:"cert"`
}

type Requirements struct {
	CredentialTypes []string
	Formula         []hwsig.Component
	ServiceURIs     []string
	Prompt          string
}

func (kc *Client) Hello() error {
	log.Debugf("Connecting to KeyTalk server at %s", kc.BaseURL.String())

	values := url.Values{
		"description": []string{"KeyTalk GO client"},
	}

	var resp helloResponse

	if req, err := kc.NewRequest(RCDPV2_REQUEST_HELLO, values); err != nil {
		return err
	} else if err := kc.Do(req, &resp); err != nil {
		return err
	}

	if resp.Version != RCDP_VERSION_2_0 {
		return fmt.Errorf("Unexpected version, expected: %s, got: %s", RCDP_VERSION_2_0, resp.Version)
	}

	return nil
}

func (kc *Client) Handshake() error {
	values := url.Values{
		RCDPV2_REQUEST_PARAM_NAME_CALLER_UTC: []string{time.Now().UTC().Format(time.RFC3339)},
	}

	var resp handshakeResponse
	if req, err := kc.NewRequest(RCDPV2_REQUEST_HANDSHAKE, values); err != nil {
		return err
	} else if err := kc.Do(req, &resp); err != nil {
		return err
	}

	if resp.Status != RCDPV2_RESPONSE_HANDSHAKE {
		return fmt.Errorf("Unexpected response: expected %s, got %s", RCDPV2_RESPONSE_HANDSHAKE, resp.Status)
	}

	return nil
}

func (kc *Client) authenticationRequirements(service string) (*Requirements, error) {
	values := url.Values{
		RCDPV2_REQUEST_PARAM_NAME_SERVICE: []string{service},
	}

	var resp authRequirementsResponse
	if req, err := kc.NewRequest(RCDPV2_REQUEST_AUTH_REQUIREMENTS, values); err != nil {
		return nil, err
	} else if err := kc.Do(req, &resp); err != nil {
		return nil, err
	}

	if resp.Status != RCDPV2_RESPONSE_AUTH_REQUIREMENTS {
		return nil, fmt.Errorf("Unexpected response: expected %s, got %s: %#v", RCDPV2_RESPONSE_AUTH_REQUIREMENTS, resp.Status, resp)
	}

	formula := []hwsig.Component{}
	for _, f := range strings.Split(resp.Formula, ",") {
		if v, err := strconv.Atoi(f); err == nil {
			formula = append(formula, hwsig.Component(v))
		}
	}

	return &Requirements{
		CredentialTypes: resp.CredentialTypes,
		Formula:         formula,
		ServiceURIs:     resp.ServiceURIs,
		Prompt:          resp.Prompt,
	}, nil
}

func (kc *Client) isCredentialResponseAuthentication(service string) error {
	// TODO: return conf.CRED_RESPONSE in auth_requirements[conf.RCDPV2_RESPONSE_PARAM_NAME_CRED_TYPES]
	return nil
}

func (kc *Client) authenticate(creds map[string]string, service string) ([]Challenge, error) {
	values := url.Values{}

	for k, v := range creds {
		values.Add(k, v)
	}

	//requirement.ServiceURI

	// RCDPV2_REQUEST_PARAM_NAME_IPS // resolve
	// RCDPV2_REQUEST_PARAM_NAME_DIGEST // sha256

	values.Add(RCDPV2_REQUEST_PARAM_NAME_SERVICE, service)
	values.Add(RCDPV2_REQUEST_PARAM_NAME_CALLER_HW_DESCRIPTION, hwsig.Description())

	var resp authenticateResponse
	if req, err := kc.NewRequest(RCDPV2_REQUEST_AUTHENTICATION, values); err != nil {
		return nil, err
	} else if err := kc.Do(req, &resp); err != nil {
		return nil, err
	}

	if resp.Status != RCDPV2_RESPONSE_AUTH_RESULT {
		return nil, fmt.Errorf("Unexpected response: expected %s, got %s", RCDPV2_RESPONSE_AUTH_RESULT, resp.Status)
	}

	if resp.AuthStatus == "OK" {
	} else if resp.AuthStatus == "CHALLENGE" {
		return resp.Challenges, nil
	} else if resp.AuthStatus == "DELAY" {
		delay, _ := strconv.Atoi(resp.Delay)
		return nil, ErrAuthDelay{
			Delay: delay,
		}
	} else {
		return nil, ErrAuth{
			Status: resp.AuthStatus,
		}
	}

	return nil, nil
}

type ErrAuth struct {
	Status string
}

func (err ErrAuth) Error() string {
	return fmt.Sprintf("Authentication failed, status %s.", err.Status)
}

type ErrAuthDelay struct {
	Delay int
}

func (ad ErrAuthDelay) Error() string {
	return fmt.Sprintf("Authentication failed, user banned for %d seconds.", ad.Delay)
}

type OptionFunc func(v url.Values)

func OptTime(t time.Time) func(v url.Values) {
	return func(v url.Values) {
		v.Add(
			RCDPV2_REQUEST_PARAM_NAME_LAST_MESSAGES_FROM_UTC, t.UTC().Format("2006-01-02T15:04:05-0700"),
		)
	}
}

// LastMessages will return the last messages from a specific date
func (kc *Client) LastMessages(opts ...OptionFunc) ([]Message, error) {
	values := url.Values{}

	for _, optFn := range opts {
		optFn(values)
	}

	var resp lastMessagesResponse
	if req, err := kc.NewRequest(RCDPV2_REQUEST_LAST_MESSAGES, values); err != nil {
		return nil, err
	} else if err := kc.Do(req, &resp); err != nil {
		return nil, err
	} else if resp.Status != RCDPV2_RESPONSE_LAST_MESSAGES {
		return nil, fmt.Errorf("Unexpected response: expected %s, got %s", RCDPV2_RESPONSE_LAST_MESSAGES, resp.Status)
	} else {
		var messages []Message
		if err := json.Unmarshal(resp.RawMessages, &messages); err == nil {
			return messages, nil
		}

		var message Message
		if err := json.Unmarshal(resp.RawMessages, &message); err == nil {
			return []Message{message}, nil
		}

		var str string
		if err := json.Unmarshal(resp.RawMessages, &str); err == nil {
			return []Message{Message{Text: str}}, nil
		}

		return nil, fmt.Errorf("Could not decode messages value")
	}
}

func (kc *Client) certificate() (*UserCertificate, error) {
	values := url.Values{
		RCDPV2_REQUEST_PARAM_NAME_CERT_FORMAT:        []string{CERT_FORMAT_P12},
		RCDPV2_REQUEST_PARAM_NAME_CERT_INCLUDE_CHAIN: []string{"false"},
	}

	var resp getCertificateResponse
	if req, err := kc.NewRequest(RCDPV2_REQUEST_CERT, values); err != nil {
		return nil, err
	} else if err := kc.Do(req, &resp); err != nil {
		return nil, err
	}

	if resp.Status != RCDPV2_RESPONSE_CERT {
		return nil, fmt.Errorf("Unexpected response: expected %s, got %s", RCDPV2_RESPONSE_CERT, resp.Status)
	}

	if der, err := base64.StdEncoding.DecodeString(resp.Cert); err != nil {
		return nil, err
	} else if pk, cert, err := pkcs12.Decode(der, kc.Token()[:RCDPV2_PACKAGED_CERT_EXPORT_PASSWDSIZE]); err != nil {
		return nil, err
	} else {
		return &UserCertificate{
			Certificate: cert,
			pk:          pk,
		}, err
	}
}

func (kc *Client) Token() string {
	u, err := url.Parse(fmt.Sprintf("%s/%s/", RCDPV2_HTTP_REQUEST_URI_PREFIX, RCDP_VERSION_2_0))
	if err != nil {
		return ""
	}

	url := kc.BaseURL.ResolveReference(u)

	if len(kc.Client.Jar.Cookies(url)) == 0 {
		return ""
	}

	password := kc.Client.Jar.Cookies(url)[0].Value // .Get(RCDPV2_HTTP_SID_COOKIE_NAME)
	return password[:]
}

func (kc *Client) SetToken(s string) error {
	u, err := url.Parse(fmt.Sprintf("%s/%s/", RCDPV2_HTTP_REQUEST_URI_PREFIX, RCDP_VERSION_2_0))
	if err != nil {
		return err
	}

	url := kc.BaseURL.ResolveReference(u)

	kc.Client.Jar.SetCookies(url, []*http.Cookie{
		&http.Cookie{
			Name:    RCDPV2_HTTP_SID_COOKIE_NAME,
			Value:   s,
			Expires: time.Now().Add(5 * time.Minute),
		},
	})

	return nil
}

func (kc *Client) eoc() error {
	if req, err := kc.NewRequest(RCDPV2_REQUEST_EOC, nil); err != nil {
		return err
	} else if err := kc.Do(req, nil); err != nil {
		return err
	}

	return nil
}

// Usercertificate contains the x509 certificate and the PrivateKey
type UserCertificate struct {
	*x509.Certificate
	pk interface{}
}

// PrivateKey will return the privateKey for the certificate
func (uc *UserCertificate) PrivateKey() interface{} {
	return uc.pk
}

func (kc *Client) Requirements(service string) (*Requirements, error) {
	return kc.authenticationRequirements(service)
}

// Authenticate will authenticate username, password and service with the Keytalk server and return
// a private key and certificate.
func (kc *Client) Authenticate(username string, password string, service string) (*AuthenticationResult, error) {
	creds := map[string]string{}

	requirements, err := kc.authenticationRequirements(service)
	if err != nil {
		return nil, err
	}

	for _, v := range requirements.CredentialTypes {
		switch v {
		case CRED_USERID:
			creds[CRED_USERID] = username
		case CRED_PASSWD:
			creds[CRED_PASSWD] = password
		case CRED_HWSIG:
			if signature, err := hwsig.Calc(requirements.Formula); err == nil {
				creds[CRED_HWSIG] = signature
			} else {
				return nil, err
			}
		}
	}

	if challenges, err := kc.authenticate(creds, service); err != nil {
		return nil, err
	} else if len(challenges) > 0 {
		return &AuthenticationResult{
			Challenges: challenges,
		}, nil
	} else if uc, err := kc.certificate(); err != nil {
		return nil, err
	} else {
		return &AuthenticationResult{
			ServiceURIs:     requirements.ServiceURIs,
			UserCertificate: uc,
		}, nil
	}
}

type AuthenticationResult struct {
	ServiceURIs []string
	Challenges  []Challenge
	*UserCertificate
}

func (kc *Client) Close() {
	kc.eoc()
}
