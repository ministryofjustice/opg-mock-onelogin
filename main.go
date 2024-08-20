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
	"io"
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
	clientId            = envGet("CLIENT_ID", "theClientId")
	internalURL         = envGet("INTERNAL_URL", "http://mock-onelogin:8080")
	port                = envGet("PORT", "8080")
	publicURL           = envGet("PUBLIC_URL", "http://localhost:8080")
	serviceRedirectUrl  = envGet("REDIRECT_URL", "http://localhost:5050/auth/redirect")
	templateHeader      = os.Getenv("TEMPLATE_HEADER") == "1"
	templateSub         = os.Getenv("TEMPLATE_SUB") == "1"
	templateEmail       = os.Getenv("TEMPLATE_EMAIL")
	templateReturnCodes = os.Getenv("TEMPLATE_RETURN_CODES") == "1"

	tokenSigningKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tokenSigningKid    = randomString("kid-", 8)

	privateKeyBytes, _ = base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSVBheDJBYW92aXlQWDF3cndmS2FWckxEOHdQbkpJcUlicTMzZm8rWHdBZDdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFSlEyVmtpZWtzNW9rSTIxY1Jma0FhOXVxN0t4TTZtMmpaWUJ4cHJsVVdCWkNFZnhxMjdwVQp0Qzd5aXplVlRiZUVqUnlJaStYalhPQjFBbDhPbHFtaXJnPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=")
	privateKey, _      = jwt.ParseECPrivateKeyFromPEM(privateKeyBytes)

	randomString = func(prefix string, length int) string {
		return prefix + stringWithCharset(length, charset)
	}
	now = time.Now

	sessions = map[string]sessionData{}
	tokens   = map[string]sessionData{}
)

type Handler func(w http.ResponseWriter, r *http.Request) error

type user struct {
	firstNames, lastName, dateOfBirth string
}

type sessionData struct {
	// email to use for the session
	email string
	// nonce to respond with
	nonce string
	// sub to use for the session
	sub string
	// user selected from identity options
	user user
	// identity is true when using the identity flow
	identity bool
	// returnCode to respond with (for failure to ID)
	returnCode string
	// address associated with the user
	address CredentialAddress
}

type OpenIdConfig struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	Issuer                string `json:"issuer"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
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
	Sub             string              `json:"sub"`
	Email           string              `json:"email"`
	EmailVerified   bool                `json:"email_verified"`
	Phone           string              `json:"phone"`
	PhoneVerified   bool                `json:"phone_verified"`
	UpdatedAt       int                 `json:"updated_at"`
	CoreIdentityJWT string              `json:"https://vocab.account.gov.uk/v1/coreIdentityJWT,omitempty"`
	ReturnCode      []ReturnCodeInfo    `json:"https://vocab.account.gov.uk/v1/returnCode,omitempty"`
	Addresses       []CredentialAddress `json:"https://vocab.account.gov.uk/v1/address,omitempty"`
}

type CredentialAddress struct {
	UPRN                           int    `json:"uprn,omitempty"`
	SubBuildingName                string `json:"subBuildingName,omitempty"`
	BuildingName                   string `json:"buildingName,omitempty"`
	BuildingNumber                 string `json:"buildingNumber,omitempty"`
	DependentStreetName            string `json:"dependentStreetName,omitempty"`
	StreetName                     string `json:"streetName,omitempty"`
	DoubleDependentAddressLocality string `json:"doubleDependentAddressLocality,omitempty"`
	DependentAddressLocality       string `json:"dependentAddressLocality,omitempty"`
	AddressLocality                string `json:"addressLocality,omitempty"`
	PostalCode                     string `json:"postalCode,omitempty"`
	AddressCountry                 string `json:"addressCountry,omitempty"`
	ValidFrom                      string `json:"validFrom,omitempty"`
	ValidUntil                     string `json:"validUntil,omitempty"`
}

type ReturnCodeInfo struct {
	Code string `json:"code"`
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

func createSignedToken(kid, nonce, sub, clientId, issuer string) (string, error) {
	t := jwt.New(jwt.SigningMethodES256)

	t.Header["kid"] = kid

	t.Claims = JWTIdToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   sub,
			Audience:  []string{clientId},
			ExpiresAt: jwt.NewNumericDate(now().Add(time.Minute * 3)),
			IssuedAt:  jwt.NewNumericDate(now()),
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

func jwks(kid string, publicKey ecdsa.PublicKey) Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "EC",
					"use": "sig",
					"crv": "P-256",
					"kid": kid,
					"x":   base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
					"y":   base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
					"alg": "ES256",
				},
			},
		})
	}
}

type authorizeTemplateData struct {
	Identity    bool
	Header      bool
	Sub         bool
	Email       string
	ReturnCodes bool
}

func authorize(tmpl interface {
	Execute(io.Writer, any) error
}) Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		returnIdentity := false
		useReturnCodes := false
		returnAddress := false

		if r.FormValue("claims") != "" {
			var claims struct {
				UserInfo map[string]any `json:"userinfo"`
			}

			if err := json.Unmarshal([]byte(r.FormValue("claims")), &claims); err != nil {
				return fmt.Errorf("claims could not be unmarshalled")
			}

			if _, ok := claims.UserInfo["https://vocab.account.gov.uk/v1/coreIdentityJWT"]; ok {
				returnIdentity = r.FormValue("vtr") == `["Cl.Cm.P2"]`
			}

			if _, ok := claims.UserInfo["https://vocab.account.gov.uk/v1/returnCode"]; ok {
				useReturnCodes = true
			}

			if _, ok := claims.UserInfo["https://vocab.account.gov.uk/v1/address"]; ok {
				returnAddress = true
			}
		}

		if r.Method == http.MethodGet {
			return tmpl.Execute(w, authorizeTemplateData{
				Identity:    returnIdentity,
				Header:      templateHeader,
				Sub:         templateSub,
				Email:       templateEmail,
				ReturnCodes: templateReturnCodes && useReturnCodes,
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
			if templateSub {
				sub = randomString("sub-", 20)
			} else {
				h := sha256.New()
				h.Write([]byte(email))
				encodedEmail := base64.StdEncoding.EncodeToString(h.Sum(nil))
				sub = "urn:fdc:mock-one-login:2023:" + encodedEmail
			}
		}

		returnCode := ""
		if useReturnCodes {
			returnCode = r.FormValue("return-code")
		}

		user, a := userDetails(r.PostForm)

		address := CredentialAddress{}
		if returnAddress {
			address = a
		}

		sessions[code] = sessionData{
			email:      email,
			nonce:      r.FormValue("nonce"),
			user:       user,
			sub:        sub,
			identity:   returnIdentity,
			returnCode: returnCode,
			address:    address,
		}

		u.RawQuery = q.Encode()

		http.Redirect(w, r, u.String(), http.StatusFound)
		return nil
	}
}

func token(kid, clientId, issuer string) Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		code := r.PostFormValue("code")
		accessToken := randomString("token-", 10)

		session := sessions[code]

		delete(sessions, code)
		tokens[accessToken] = session

		t, err := createSignedToken(kid, session.nonce, session.sub, clientId, issuer)
		if err != nil {
			return fmt.Errorf("error creating jwt: %w", err)
		}

		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			IDToken:     t,
		})
	}
}

func userInfo() Handler {
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
			if token.returnCode != "" {
				userInfo.ReturnCode = append(userInfo.ReturnCode, ReturnCodeInfo{Code: token.returnCode})
			} else {
				claims := JWTCoreIdentity{
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    "https://identity.account.gov.uk/", // production identity url
						Subject:   token.sub,
						Audience:  []string{clientId},
						ExpiresAt: jwt.NewNumericDate(now().Add(time.Minute * 3)),
						IssuedAt:  jwt.NewNumericDate(now()),
						NotBefore: jwt.NewNumericDate(now()),
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
										{"type": "GivenName", "value": token.user.firstNames},
										{"type": "FamilyName", "value": token.user.lastName},
									},
								},
							},
							"birthDate": []map[string]any{
								{
									"value": token.user.dateOfBirth,
								},
							},
						},
					},
				}

				userInfo.Addresses = append(userInfo.Addresses, token.address)
				userInfo.CoreIdentityJWT, _ = jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(privateKey)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(userInfo)
	}
}

func logout() Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		idToken := r.FormValue("id_token_hint")
		postLogoutRedirectUri := r.FormValue("post_logout_redirect_uri")

		if idToken == "" && postLogoutRedirectUri != "" {
			return fmt.Errorf("query param 'post_logout_redirect_uri' specified when token param was not")
		}

		// default behaviour according to docs.
		if postLogoutRedirectUri == "" {
			http.Redirect(w, r, "https://signin.account.gov.uk/signed-out", http.StatusFound)
		}

		u, parseErr := url.Parse(postLogoutRedirectUri)
		if parseErr != nil {
			return fmt.Errorf("error parsing redirect_uri: %w", parseErr)
		}

		http.Redirect(w, r, u.String(), http.StatusFound)
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
		EndSessionEndpoint:    publicURL + "/logout",
	}

	templates, err := template.ParseFiles("web/templates/authorize.gohtml")
	if err != nil {
		return err
	}

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
	handle("/.well-known/jwks", jwks(tokenSigningKid, tokenSigningKey.PublicKey))
	handle("/authorize", authorize(templates))
	handle("/token", token(tokenSigningKid, clientId, c.Issuer))
	handle("/userinfo", userInfo())
	handle("/logout", logout())

	mux.Handle("/static/", http.StripPrefix("/static", http.FileServer(http.Dir("web/static/"))))

	logger.Info("started", slog.String("port", port))
	return http.ListenAndServe(":"+port, mux)
}

func userDetails(form url.Values) (user, CredentialAddress) {
	address := CredentialAddress{
		UPRN:                     100071428503,
		BuildingNumber:           "1",
		StreetName:               "RICHMOND PLACE",
		DependentAddressLocality: "KINGS HEATH",
		AddressLocality:          "BIRMINGHAM",
		PostalCode:               "B14 7ED",
		AddressCountry:           "GB",
		ValidFrom:                "2021-01-01",
	}

	switch form.Get("user") {
	case "donor":
		return user{"Sam", "Smith", "2000-01-02"}, address
	case "certificate-provider":
		address.BuildingNumber = "2"
		return user{"Charlie", "Cooper", "1990-01-02"}, address
	case "voucher":
		return user{"Vivian", "Vaughn", "1995-01-02"}, address
	case "custom":
		user := user{form.Get("first-names"), form.Get("last-name"), fmt.Sprintf("%s-%s-%s", form.Get("year"), zeroPad(form.Get("month")), zeroPad(form.Get("day")))}

		address := CredentialAddress{
			UPRN:                     123,
			BuildingNumber:           form.Get("building-number"),
			StreetName:               form.Get("street-name"),
			DependentAddressLocality: form.Get("line-2"),
			AddressLocality:          form.Get("town"),
			PostalCode:               form.Get("post-code"),
			AddressCountry:           "GB",
			ValidFrom:                "2021-01-01",
		}

		return user, address
	default:
		return user{}, CredentialAddress{}
	}
}

func zeroPad(s string) string {
	if len(s) == 1 {
		return "0" + s
	}

	return s
}

// Get the key from environment, if not set or empty returns def.
func envGet(key, def string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return def
}
