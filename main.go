package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	clientId           = envGet("CLIENT_ID", "theClientId")
	internalURL        = envGet("INTERNAL_URL", "http://mock-onelogin:8080")
	port               = envGet("PORT", "8080")
	publicURL          = envGet("PUBLIC_URL", "http://localhost:8080")
	serviceRedirectUrl = envGet("REDIRECT_URL", "http://localhost:5050/auth/redirect")
	templateName       = envGet("TEMPLATE", "use-an-lpa.gohtml")

	tokenSigningKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tokenSigningKid    = randomString("kid-", 8)

	sessions = map[string]sessionData{}
	tokens   = map[string]sessionData{}
)

type Handler func(w http.ResponseWriter, r *http.Request) error

type sessionData struct {
	// email to use for the session
	email string
	// nonce to respond with
	nonce string
	// sub to use for the session
	sub string
	// user selected from identity options
	user string
	// identity is true when using the identity flow
	identity bool
}

type OpenIdConfig struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	Issuer                string `json:"issuer"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
}

type JWTIdToken struct {
	jwt.RegisteredClaims

	Nonce string `json:"nonce"`
}

type UserInfoResponse struct {
	Sub             string `json:"sub"`
	Email           string `json:"email"`
	EmailVerified   bool   `json:"email_verified"`
	Phone           string `json:"phone"`
	PhoneVerified   bool   `json:"phone_verified"`
	UpdatedAt       int    `json:"updated_at"`
	CoreIdentityJWT string `json:"https://vocab.account.gov.uk/v1/coreIdentityJWT,omitempty"`
}

type JWTCoreIdentity struct {
	jwt.RegisteredClaims

	VectorOfTrust        string         `json:"vot,omitempty"`
	VectorTrustMark      string         `json:"vtm,omitempty"`
	VerifiableCredential map[string]any `json:"vc,omitempty"`
}

func stringWithCharset(length int, charset string) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	return string(bytes)
}

func randomString(prefix string, length int) string {
	return prefix + stringWithCharset(length, charset)
}

func createSignedToken(nonce, sub, clientId, issuer string) (string, error) {
	t := jwt.New(jwt.SigningMethodES256)

	t.Header["kid"] = tokenSigningKid

	t.Claims = JWTIdToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   sub,
			Audience:  []string{clientId},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 3)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce: nonce,
	}

	return t.SignedString(tokenSigningKey)
}

func openIDConfig(c OpenIdConfig) Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(c)
	}
}

func jwks() Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		publicKey := tokenSigningKey.PublicKey

		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "EC",
					"use": "sig",
					"crv": "P-256",
					"kid": tokenSigningKid,
					"x":   base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
					"y":   base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
					"alg": "ES256",
				},
			},
		})
	}
}

func token(clientId, issuer string) Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		code := r.PostFormValue("code")
		accessToken := randomString("token-", 10)

		session := sessions[code]
		delete(sessions, code)
		tokens[accessToken] = session

		t, err := createSignedToken(session.nonce, session.sub, clientId, issuer)
		if err != nil {
			return fmt.Errorf("error creating jwt: %w", err)
		}

		return json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			IDToken:     t,
		})
	}
}

type autorizeTemplateData struct {
	Identity bool
}

func authorize(tmpl *template.Template) Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		returnIdentity := false

		if r.FormValue("claims") != "" {
			var claims struct {
				UserInfo map[string]any
			}

			if err := json.Unmarshal([]byte(r.FormValue("claims")), &claims); err != nil {
				return fmt.Errorf("claims could not be unmarshalled")
			}

			if _, ok := claims.UserInfo["https://vocab.account.gov.uk/v1/coreIdentityJWT"]; ok {
				returnIdentity = r.FormValue("vtr") == `["Cl.Cm.P2"]`
			}
		}

		if r.Method == http.MethodGet {
			return tmpl.ExecuteTemplate(w, templateName, autorizeTemplateData{
				Identity: returnIdentity,
			})
		}

		redirectUri := r.FormValue("redirect_uri")
		if redirectUri == "" {
			return fmt.Errorf("required query param 'redirect_uri' missing from request")
		}

		if redirectUri != serviceRedirectUrl {
			return fmt.Errorf("redirect_uri does not match pre-defined redirect URL (in RL this is set with GDS at a service level). Got %s, want %s", redirectUri, serviceRedirectUrl)
		}

		u, parseErr := url.Parse(redirectUri)
		if parseErr != nil {
			return fmt.Errorf("error parsing redirect_uri: %w", parseErr)
		}

		q := u.Query()

		code := randomString("code-", 10)
		q.Set("code", code)
		q.Set("state", r.FormValue("state"))

		email := r.FormValue("email")
		if email == "" {
			email = "simulate-delivered@notifications.service.gov.uk"
		}

		sub := r.FormValue("sub")
		if sub == "" {
			h := sha256.New()
			h.Write([]byte(email))
			encodedEmail := base64.StdEncoding.EncodeToString(h.Sum(nil))
			sub = "urn:fdc:mock-one-login:2023:" + encodedEmail
		}

		sessions[code] = sessionData{
			email:    email,
			nonce:    r.FormValue("nonce"),
			user:     r.FormValue("user"),
			sub:      sub,
			identity: returnIdentity,
		}

		u.RawQuery = q.Encode()

		http.Redirect(w, r, u.String(), 302)
		return nil
	}
}

func userInfo(privateKey *ecdsa.PrivateKey) Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		token := tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if token.email == "" {
			return nil
		}

		//hard coded values need to pull out
		userInfo := UserInfoResponse{
			Sub:           token.sub,
			Email:         token.email,
			EmailVerified: true,
			Phone:         "01406946277",
			PhoneVerified: true,
			UpdatedAt:     1311280970,
		}

		if token.identity {
			givenName, familyName, birthDate := userDetails(token.user)

			claims := JWTCoreIdentity{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "https://identity.account.gov.uk/", // production identity url
					Subject:   token.sub,
					Audience:  []string{clientId},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 3)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
				},
				VectorOfTrust:   "P2",
				VectorTrustMark: "https://oidc.account.gov.uk/trustmark", // production trustmark url
				VerifiableCredential: map[string]any{
					"type": []string{
						"VerifiableCredential",
						"VerifiableIdentityCredential",
					},
					"credentialSubject": map[string]any{
						"name": []map[string]any{
							{
								"validFrom": "2000-01-01",
								"nameParts": []map[string]any{
									{"type": "GivenName", "value": givenName},
									{"type": "FamilyName", "value": familyName},
								},
							},
						},
						"birthDate": []map[string]any{
							{
								"value": birthDate,
							},
						},
					},
				},
			}

			userInfo.CoreIdentityJWT, _ = jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(privateKey)
		}

		return json.NewEncoder(w).Encode(userInfo)
	}
}

func logout() Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		postLogoutRedirectUri := r.FormValue("post_logout_redirect_uri")

		if postLogoutRedirectUri == "" {
			return fmt.Errorf("required query param 'post_logout_redirect_uri' missing from request")
		}

		u, parseErr := url.Parse(postLogoutRedirectUri)
		if parseErr != nil {
			return fmt.Errorf("error parsing redirect_uri: %w", parseErr)
		}

		http.Redirect(w, r, u.String(), 302)
		return nil
	}
}

func main() {
	logger := slog.New(slog.
		NewJSONHandler(os.Stdout, nil).
		WithAttrs([]slog.Attr{slog.String("service_name", "opg-mock-onelogin")}))

	if err := run(logger); err != nil {
		logger.Error("run error", slog.Any("err", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	c := OpenIdConfig{
		Issuer:                publicURL,
		AuthorizationEndpoint: publicURL + "/authorize",
		TokenEndpoint:         internalURL + "/token",
		UserinfoEndpoint:      internalURL + "/userinfo",
		JwksURI:               internalURL + "/.well-known/jwks",
	}

	templates, err := template.ParseGlob("web/templates/*.*")
	if err != nil {
		return err
	}

	privateKeyBytes, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSVBheDJBYW92aXlQWDF3cndmS2FWckxEOHdQbkpJcUlicTMzZm8rWHdBZDdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFSlEyVmtpZWtzNW9rSTIxY1Jma0FhOXVxN0t4TTZtMmpaWUJ4cHJsVVdCWkNFZnhxMjdwVQp0Qzd5aXplVlRiZUVqUnlJaStYalhPQjFBbDhPbHFtaXJnPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=")
	privateKey, _ := jwt.ParseECPrivateKeyFromPEM(privateKeyBytes)

	jwt.MarshalSingleStringAsArray = false

	mux := http.NewServeMux()
	handle := func(path string, h Handler) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if err := h(w, r); err != nil {
				logger.Error(r.Method+" "+r.URL.Path, slog.Any("err", err.Error()))
				http.Error(w, "there was a problem", http.StatusInternalServerError)
				return
			}

			logger.Info(r.Method + " " + r.URL.Path)
		})
	}

	handle("/.well-known/openid-configuration", openIDConfig(c))
	handle("/.well-known/jwks", jwks())
	handle("/authorize", authorize(templates))
	handle("/token", token(clientId, c.Issuer))
	handle("/userinfo", userInfo(privateKey))
	handle("/logout", logout())

	mux.Handle("/static/", http.StripPrefix("/static", http.FileServer(http.Dir("web/static/"))))

	logger.Info("started", slog.String("port", port))
	return http.ListenAndServe(":"+port, mux)
}

func userDetails(key string) (givenName, familyName, birthDate string) {
	switch key {
	case "donor":
		return "Sam", "Smith", "2000-01-02"
	case "attorney":
		return "Amy", "Adams", "1980-01-02"
	case "certificate-provider":
		return "Charlie", "Cooper", "1990-01-02"
	default:
		return "Someone", "Else", "2000-01-02"
	}
}

// Get the key from environment, if not set or empty returns def.
func envGet(key, def string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return def
}
