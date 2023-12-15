package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	gotemplate "html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/ministryofjustice/opg-go-common/env"
	"github.com/ministryofjustice/opg-go-common/template"
)

var (
	port               = env.Get("PORT", "8080")
	publicURL          = env.Get("PUBLIC_URL", "http://localhost:8080")
	internalURL        = env.Get("INTERNAL_URL", "http://mock-onelogin:8080")
	clientId           = env.Get("CLIENT_ID", "theClientId")
	serviceRedirectUrl = env.Get("REDIRECT_URL", "http://localhost:5050/auth/redirect")

	signingKid    = "my-kid"
	signingKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	sessions = map[string]sessionData{}
	tokens   = map[string]sessionData{}

	templates = template.Templates{}
)

type sessionData struct {
	email    string
	nonce    string
	sub      string
	user     string
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

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

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

func randomString(length int) string {
	return stringWithCharset(length, charset)
}

func createSignedToken(nonce, sub, clientId, issuer string) (string, error) {
	t := jwt.New(jwt.SigningMethodES256)

	t.Header["kid"] = signingKid

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

	return t.SignedString(signingKey)
}

func openIDConfig(c OpenIdConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c)
	}
}

func jwks() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		publicKey := signingKey.PublicKey

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "EC",
					"use": "sig",
					"crv": "P-256",
					"kid": signingKid,
					"x":   base64.URLEncoding.EncodeToString(publicKey.X.Bytes()),
					"y":   base64.URLEncoding.EncodeToString(publicKey.Y.Bytes()),
					"alg": "ES256",
				},
			},
		})
	}
}

func token(clientId, issuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.PostFormValue("code")
		accessToken := randomString(10)

		session := sessions[code]
		delete(sessions, code)
		tokens[accessToken] = session

		t, err := createSignedToken(session.nonce, session.sub, clientId, issuer)
		if err != nil {
			log.Fatalf("Error creating JWT: %s", err)
		}

		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			IDToken:     t,
		})
	}
}

func authorize() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("/authorize")

		returnIdentity := r.FormValue("vtr") == `["Cl.Cm.P2"]` && r.FormValue("claims") == `{"userinfo":{"https://vocab.account.gov.uk/v1/coreIdentityJWT":null}}`

		if r.Method == http.MethodGet {
			t := templates.Get("home.page.gohtml")
			if err := t(w, struct {
				ReturnIdentity bool
			}{
				ReturnIdentity: returnIdentity,
			}); err != nil {
				log.Fatal("Failed to render template")
			}
			return
		}

		redirectUri := r.FormValue("redirect_uri")
		if redirectUri == "" {
			log.Fatal("Required query param 'redirect_uri' missing from request")
		}

		if redirectUri != serviceRedirectUrl {
			log.Fatalf("redirect_uri does not match pre-defined redirect URL (in RL this is set with GDS at a service level). Got %s, want %s", redirectUri, serviceRedirectUrl)
		}

		u, parseErr := url.Parse(redirectUri)
		if parseErr != nil {
			log.Fatalf("Error parsing redirect_uri: %s", parseErr)
		}

		q := u.Query()

		code := randomString(10)
		q.Set("code", code)
		q.Set("state", r.FormValue("state"))

		email := r.FormValue("email")
		h := sha256.New()
		h.Write([]byte(email))
		encodedEmail := base64.StdEncoding.EncodeToString(h.Sum(nil))

		sessions[code] = sessionData{
			email:    email,
			nonce:    r.FormValue("nonce"),
			user:     r.FormValue("user"),
			sub:      "urn:fdc:mock-one-login:2023:" + encodedEmail,
			identity: returnIdentity,
		}

		u.RawQuery = q.Encode()

		log.Printf("Redirecting to %s with nonce %s and email %s with sub %s", u.String(), sessions[code].nonce, sessions[code].email, sessions[code].sub)

		http.Redirect(w, r, u.String(), 302)
	}
}

func userInfo(privateKey *ecdsa.PrivateKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		token := tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if token.email == "" {
			return
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

		json.NewEncoder(w).Encode(userInfo)
	}
}

func logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("/logout was called")
		postLogoutRedirectUri := r.FormValue("post_logout_redirect_uri")

		if postLogoutRedirectUri == "" {
			log.Fatal("Required query param 'post_logout_redirect_uri' missing from request")
		}

		u, parseErr := url.Parse(postLogoutRedirectUri)
		if parseErr != nil {
			log.Fatalf("Error parsing redirect_uri: %s", parseErr)
		}

		log.Printf("Redirecting to %s", u.String())
		http.Redirect(w, r, u.String(), 302)
	}
}

func main() {
	flag.Parse()

	c := OpenIdConfig{
		Issuer:                publicURL,
		AuthorizationEndpoint: publicURL + "/authorize",
		TokenEndpoint:         internalURL + "/token",
		UserinfoEndpoint:      internalURL + "/userinfo",
		JwksURI:               internalURL + "/.well-known/jwks",
	}

	var err error
	templates, err = template.Parse("web/templates", gotemplate.FuncMap{})
	if err != nil {
		panic(err)
	}

	privateKeyBytes, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSVBheDJBYW92aXlQWDF3cndmS2FWckxEOHdQbkpJcUlicTMzZm8rWHdBZDdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFSlEyVmtpZWtzNW9rSTIxY1Jma0FhOXVxN0t4TTZtMmpaWUJ4cHJsVVdCWkNFZnhxMjdwVQp0Qzd5aXplVlRiZUVqUnlJaStYalhPQjFBbDhPbHFtaXJnPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=")
	privateKey, _ := jwt.ParseECPrivateKeyFromPEM(privateKeyBytes)

	jwt.MarshalSingleStringAsArray = false

	http.HandleFunc("/.well-known/openid-configuration", openIDConfig(c))
	http.HandleFunc("/.well-known/jwks", jwks())
	http.HandleFunc("/authorize", authorize())
	http.HandleFunc("/token", token(clientId, c.Issuer))
	http.HandleFunc("/userinfo", userInfo(privateKey))
	http.HandleFunc("/logout", logout())

	log.Println("GOV UK Sign in mock initialized")

	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), logRoute(http.DefaultServeMux)); err != nil {
		panic(err)
	}
}

func logRoute(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.URL.Path)
		h.ServeHTTP(w, r)
	}
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
