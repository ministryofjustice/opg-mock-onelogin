package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	randomString = func(prefix string, length int) string {
		return "random"
	}

	now = func() time.Time {
		return time.Date(2020, time.January, 2, 3, 4, 5, 6, time.UTC)
	}

	code := m.Run()
	os.Exit(code)
}

func TestOpenIDConfig(t *testing.T) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)

	h := openIDConfig(OpenIdConfig{
		AuthorizationEndpoint: "a",
		Issuer:                "b",
		TokenEndpoint:         "c",
		UserinfoEndpoint:      "d",
		JwksURI:               "e",
		EndSessionEndpoint:    "f",
	})
	err := h(w, r)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assert.Nil(t, err)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.JSONEq(t, `{"authorization_endpoint":"a","issuer":"b","token_endpoint":"c","userinfo_endpoint":"d","jwks_uri":"e","end_session_endpoint":"f"}`, string(body))
}

func TestJwks(t *testing.T) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)

	h := jwks("my-kid", ecdsa.PublicKey{X: big.NewInt(1), Y: big.NewInt(2)})
	err := h(w, r)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assert.Nil(t, err)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.JSONEq(t, `{"keys":[{"kty":"EC","use":"sig","crv":"P-256","kid":"my-kid","x":"AQ","y":"Ag","alg":"ES256"}]}`, string(body))
}

func TestToken(t *testing.T) {
	form := url.Values{
		"code": {"my-code"},
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	session := sessionData{user: user{"x", "y", "z"}}
	sessions["my-code"] = session

	h := token("my-kid", "my-client", "http://issuer")
	err := h(w, r)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	var data map[string]string
	json.Unmarshal(body, &data)

	assert.Nil(t, err)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, "random", data["access_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.Contains(t, data["id_token"], "eyJhbGciOiJFUzI1NiIsImtpZCI6Im15LWtpZCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vaXNzdWVyIiwiYXVkIjpbIm15LWNsaWVudCJdLCJleHAiOjE1Nzc5MzQ0MjUsImlhdCI6MTU3NzkzNDI0NSwibm9uY2UiOiIifQ.")

	assert.Equal(t, map[string]sessionData{"random": session}, tokens)
	assert.Equal(t, map[string]sessionData{}, sessions)
}

type mockTemplate struct {
	w    io.Writer
	name string
	data any
}

func (m *mockTemplate) Execute(w io.Writer, data any) error {
	m.w = w
	m.data = data
	return nil
}

func TestAuthorize(t *testing.T) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)

	template := &mockTemplate{}

	h := authorize(template)
	err := h(w, r)

	assert.Nil(t, err)
	assert.Equal(t, w, template.w)
	assert.Equal(t, authorizeTemplateData{}, template.data)
}

func TestAuthorizeWithIdentity(t *testing.T) {
	form := url.Values{
		"vtr":    {`["Cl.Cm.P2"]`},
		"claims": {`{"userinfo":{"https://vocab.account.gov.uk/v1/coreIdentityJWT":null}}`},
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/?"+form.Encode(), nil)

	template := &mockTemplate{}

	h := authorize(template)
	err := h(w, r)

	assert.Nil(t, err)
	assert.Equal(t, w, template.w)
	assert.Equal(t, authorizeTemplateData{Identity: true}, template.data)
}

func TestAuthorizePost(t *testing.T) {
	testcases := map[string]struct {
		form    url.Values
		session sessionData
	}{
		"sign-in": {
			form: url.Values{
				"redirect_uri": {"http://localhost:5050/auth/redirect"},
				"state":        {"my-state"},
				"nonce":        {"my-nonce"},
			},
			session: sessionData{
				email: "simulate-delivered@notifications.service.gov.uk",
				nonce: "my-nonce",
				sub:   "urn:fdc:mock-one-login:2023:QMykNslde7HiDDtluNUVQUUnFpbu1ZAKiOr/QZ6sY34=",
			},
		},
		"sign-in with email": {
			form: url.Values{
				"redirect_uri": {"http://localhost:5050/auth/redirect"},
				"state":        {"my-state"},
				"nonce":        {"my-nonce"},
				"email":        {"dave@example.com"},
			},
			session: sessionData{
				email: "dave@example.com",
				nonce: "my-nonce",
				sub:   "urn:fdc:mock-one-login:2023:ezQhE1D/Vnlwl04eK5jTGaYBlp50/RqVe8iJuDMtAOs=",
			},
		},
		"sign-in with sub": {
			form: url.Values{
				"redirect_uri": {"http://localhost:5050/auth/redirect"},
				"state":        {"my-state"},
				"nonce":        {"my-nonce"},
				"sub":          {"dave"},
			},
			session: sessionData{
				email: "simulate-delivered@notifications.service.gov.uk",
				nonce: "my-nonce",
				sub:   "dave",
			},
		},
		"sign-in with email and sub": {
			form: url.Values{
				"redirect_uri": {"http://localhost:5050/auth/redirect"},
				"state":        {"my-state"},
				"nonce":        {"my-nonce"},
				"email":        {"dave@example.com"},
				"sub":          {"dave"},
			},
			session: sessionData{
				email: "dave@example.com",
				nonce: "my-nonce",
				sub:   "dave",
			},
		},
		"identity": {
			form: url.Values{
				"redirect_uri": {"http://localhost:5050/auth/redirect"},
				"state":        {"my-state"},
				"nonce":        {"my-nonce"},
				"vtr":          {`["Cl.Cm.P2"]`},
				"claims":       {`{"userinfo":{"https://vocab.account.gov.uk/v1/coreIdentityJWT":null}}`},
				"user":         {"donor"},
			},
			session: sessionData{
				email:    "simulate-delivered@notifications.service.gov.uk",
				nonce:    "my-nonce",
				sub:      "urn:fdc:mock-one-login:2023:QMykNslde7HiDDtluNUVQUUnFpbu1ZAKiOr/QZ6sY34=",
				identity: true,
				user: user{
					firstNames:  "Sam",
					lastName:    "Smith",
					dateOfBirth: "2000-01-02",
				},
			},
		},
		"custom identity": {
			form: url.Values{
				"redirect_uri": {"http://localhost:5050/auth/redirect"},
				"state":        {"my-state"},
				"nonce":        {"my-nonce"},
				"vtr":          {`["Cl.Cm.P2"]`},
				"claims":       {`{"userinfo":{"https://vocab.account.gov.uk/v1/coreIdentityJWT":null}}`},
				"user":         {"custom"},
				"first-names":  {"John"},
				"last-name":    {"Smith"},
				"day":          {"1"},
				"month":        {"2"},
				"year":         {"3"},
			},
			session: sessionData{
				email:    "simulate-delivered@notifications.service.gov.uk",
				nonce:    "my-nonce",
				sub:      "urn:fdc:mock-one-login:2023:QMykNslde7HiDDtluNUVQUUnFpbu1ZAKiOr/QZ6sY34=",
				identity: true,
				user: user{
					firstNames:  "John",
					lastName:    "Smith",
					dateOfBirth: "3-02-01",
				},
			},
		},
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(tc.form.Encode()))
			r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			h := authorize(nil)
			err := h(w, r)
			resp := w.Result()

			assert.Nil(t, err)
			assert.Equal(t, http.StatusFound, resp.StatusCode)
			assert.Equal(t, "http://localhost:5050/auth/redirect?code=random&state=my-state", resp.Header.Get("Location"))
			assert.Equal(t, map[string]sessionData{"random": tc.session}, sessions)
		})
	}
}

func TestUserInfo(t *testing.T) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Add("Authorization", "Bearer my-token")

	tokens["my-token"] = sessionData{
		sub:   "my-sub",
		email: "my-email",
	}

	h := userInfo()
	err := h(w, r)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assert.Nil(t, err)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.JSONEq(t, `{"sub":"my-sub","email":"my-email","email_verified":true,"phone":"01406946277","phone_verified":true,"updated_at":1311280970}`, string(body))
}

func TestUserInfoWithIdentity(t *testing.T) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Add("Authorization", "Bearer my-token")

	tokens["my-token"] = sessionData{
		user:     user{"Sam", "Smith", "2000-01-02"},
		sub:      "my-sub",
		email:    "my-email",
		identity: true,
	}

	h := userInfo()
	err := h(w, r)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	var data map[string]any
	json.Unmarshal(body, &data)

	assert.Nil(t, err)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, "my-sub", data["sub"])
	assert.Equal(t, "my-email", data["email"])
	assert.Equal(t, true, data["email_verified"])
	assert.Equal(t, "01406946277", data["phone"])
	assert.Equal(t, true, data["phone_verified"])
	assert.Equal(t, float64(1311280970), data["updated_at"])
	assert.Contains(t, data["https://vocab.account.gov.uk/v1/coreIdentityJWT"], "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lkZW50aXR5LmFjY291bnQuZ292LnVrLyIsInN1YiI6Im15LXN1YiIsImF1ZCI6WyJ0aGVDbGllbnRJZCJdLCJleHAiOjE1Nzc5MzQ0MjUsIm5iZiI6MTU3NzkzNDI0NSwiaWF0IjoxNTc3OTM0MjQ1LCJ2b3QiOiJQMiIsInZ0bSI6Imh0dHBzOi8vb2lkYy5hY2NvdW50Lmdvdi51ay90cnVzdG1hcmsiLCJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMjAwMC0wMS0wMiJ9XSwibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJTYW0ifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJTbWl0aCJ9XSwidmFsaWRGcm9tIjoiMjAwMC0wMS0wMSJ9XX0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJWZXJpZmlhYmxlSWRlbnRpdHlDcmVkZW50aWFsIl19fQ.")
}

func TestLogout(t *testing.T) {
	form := url.Values{
		"id_token_hint":            {"testtoken"},
		"post_logout_redirect_uri": {"http://somewhere"},
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/?"+form.Encode(), nil)

	h := logout()
	err := h(w, r)
	resp := w.Result()

	assert.Nil(t, err)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "http://somewhere", resp.Header.Get("Location"))
}
