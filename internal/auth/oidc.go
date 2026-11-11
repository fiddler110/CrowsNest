package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Discover reads issuer's OpenID Connect discovery document and returns the
// authorization and token endpoints. It checks the document names the same
// issuer (so one provider can't vouch for another), that the endpoints are
// https, and that PKCE with S256 is not ruled out.
func Discover(ctx context.Context, client *http.Client, issuer string) (authURL, tokenURL string, err error) {
	if client == nil {
		client = tokenClient
	}
	issuer = strings.TrimRight(issuer, "/")
	if _, err := httpsOrLocal(issuer); err != nil {
		return "", "", fmt.Errorf("the issuer %s", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req) // #nosec G704 -- the issuer is entered by an admin who re-typed their password to save it
	if err != nil {
		return "", "", fmt.Errorf("could not reach %s: %w", issuer, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("%s answered %d (is the issuer URL right? it is the address before /.well-known/openid-configuration)", issuer, resp.StatusCode)
	}
	var doc struct {
		Issuer     string   `json:"issuer"`
		AuthURL    string   `json:"authorization_endpoint"`
		TokenURL   string   `json:"token_endpoint"`
		Challenges []string `json:"code_challenge_methods_supported"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponse)).Decode(&doc); err != nil {
		return "", "", errors.New("the discovery document is not JSON")
	}
	if strings.TrimRight(doc.Issuer, "/") != issuer {
		return "", "", fmt.Errorf("the discovery document says its issuer is %q, not %q", doc.Issuer, issuer)
	}
	for name, v := range map[string]string{"authorization_endpoint": doc.AuthURL, "token_endpoint": doc.TokenURL} {
		if _, err := httpsOrLocal(v); err != nil {
			return "", "", fmt.Errorf("the discovery document's %s %s", name, err)
		}
	}
	if len(doc.Challenges) > 0 {
		ok := false
		for _, c := range doc.Challenges {
			ok = ok || c == "S256"
		}
		if !ok {
			return "", "", errors.New("this provider does not support PKCE with S256, which CrowsNest requires")
		}
	}
	return doc.AuthURL, doc.TokenURL, nil
}

// OIDCLogin serves sign-in through the providers in Store, and through
// Google, which is the built-in provider GoogleProviderID.
type OIDCLogin struct {
	Store   *OIDCStore
	Google  *GoogleLogin
	Users   *UserStore
	Service *Service

	HTTPClient *http.Client // for tests
	Now        func() time.Time
}

func (o *OIDCLogin) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *OIDCLogin) client() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return tokenClient
}

// Allows reports whether username can sign in through some enabled provider.
func (o *OIDCLogin) Allows(username string) bool {
	if o == nil || o.Store == nil || !o.Store.AnyEnabled() {
		return false
	}
	rec, ok := o.Users.Lookup(username)
	return ok && rec.OIDCEmail != ""
}

// StartURL is the absolute start URL for p, on its redirect URL's origin so
// the state cookie is set on the host the callback returns to.
func (p OIDCProvider) StartURL() string {
	u, err := url.Parse(p.RedirectURL)
	if err != nil {
		return OIDCStartPath(p.ID)
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: OIDCStartPath(p.ID)}).String()
}

func (o *OIDCLogin) provider(id string) (OIDCProvider, bool) {
	if id == GoogleProviderID {
		if !o.Google.Active() {
			return OIDCProvider{}, false
		}
		return o.Google.Provider(), true
	}
	if o.Store == nil {
		return OIDCProvider{}, false
	}
	p, ok := o.Store.Get(id)
	return p, ok && p.Enabled
}

// ServeStart sends the browser to provider id's consent screen.
func (o *OIDCLogin) ServeStart(w http.ResponseWriter, r *http.Request, id string) {
	p, ok := o.provider(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	st := oauthState{State: randomToken(), Nonce: randomToken(), Verifier: randomToken(), ExpiresAt: o.now().Add(oauthStateTTL).Unix(), Provider: p.ID}
	if st.State == "" || st.Nonce == "" || st.Verifier == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	value, err := o.Service.Sessions.signPurpose("oauth-state", st)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// #nosec G124 -- HttpOnly and SameSite=Lax always (the callback is a top-level navigation back from the provider); Secure follows server.secure_cookies
	http.SetCookie(w, &http.Cookie{Name: oauthStateCookie, Value: value, Path: oauthCookiePath, MaxAge: int(oauthStateTTL.Seconds()),
		HttpOnly: true, Secure: o.Service.SecureCookies, SameSite: http.SameSiteLaxMode})
	challenge := sha256.Sum256([]byte(st.Verifier))
	q := url.Values{
		"client_id": {p.ClientID}, "redirect_uri": {p.RedirectURL}, "response_type": {"code"},
		"scope": {"openid email"}, "state": {st.State}, "nonce": {st.Nonce},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"},
	}
	if p.ID == GoogleProviderID {
		q.Set("prompt", "select_account") // always offer the account chooser
		q.Set("access_type", "online")    // no refresh token wanted
	}
	w.Header().Set("Cache-Control", "no-store")
	sep := "?"
	if strings.Contains(p.AuthURL, "?") {
		sep = "&"
	}
	http.Redirect(w, r, p.AuthURL+sep+q.Encode(), http.StatusFound)
}

func (o *OIDCLogin) fail(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(code), http.StatusSeeOther)
}

// ServeCallback finishes sign-in for provider id.
func (o *OIDCLogin) ServeCallback(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	p, ok := o.provider(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if o.Service.LoginLimiter != nil && !o.Service.LoginLimiter.Allow(ClientIP(r, o.Service.TrustedProxies)) {
		o.fail(w, r, LoginErrorRateLimit)
		return
	}
	var st oauthState
	c, err := r.Cookie(oauthStateCookie)
	valid := err == nil && o.Service.Sessions.verifyPurpose("oauth-state", c.Value, &st) == nil &&
		st.State != "" && st.Nonce != "" && st.Verifier != "" && o.now().Unix() <= st.ExpiresAt && st.Provider == p.ID
	// #nosec G124 -- clears the state cookie; same attributes as when it was set
	http.SetCookie(w, &http.Cookie{Name: oauthStateCookie, Value: "", Path: oauthCookiePath, MaxAge: -1, Expires: time.Unix(0, 0),
		HttpOnly: true, Secure: o.Service.SecureCookies, SameSite: http.SameSiteLaxMode})
	q := r.URL.Query()
	if q.Get("error") != "" {
		o.fail(w, r, LoginErrorDenied)
		return
	}
	if !valid || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		o.fail(w, r, LoginErrorExpired)
		return
	}
	code := q.Get("code")
	if code == "" {
		o.fail(w, r, LoginErrorFailed)
		return
	}
	claims, err := o.exchange(r.Context(), p, code, st)
	if err != nil {
		log.Printf("auth: %s sign-in failed: %v", p.Name, err)
		o.fail(w, r, LoginErrorFailed)
		return
	}
	username, err := o.resolve(p, claims)
	if err != nil {
		log.Printf("audit: %s sign-in refused: %v", p.Name, err)
		o.fail(w, r, LoginErrorNotAllowed)
		return
	}
	if err := o.Service.startSession(w, username); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("audit: %s signed in with %s", username, p.Name)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type oidcClaims struct {
	sub, email string
	verified   bool
}

// resolve names the user an identity may sign in as. A subject already
// linked decides it (so a changed or reused email can't take the account
// over); the first time, a verified email matching a user's OIDC email is
// linked to that subject for good.
func (o *OIDCLogin) resolve(p OIDCProvider, c oidcClaims) (string, error) {
	if p.ID == GoogleProviderID {
		// Google keeps its email allowlist (env and users file); validate has
		// already insisted on a verified address.
		name, ok := o.Google.Lookup(c.email)
		if !ok {
			return "", fmt.Errorf("%q is not on the Google allowlist", c.email)
		}
		return name, nil
	}
	if name, ok := o.Store.LinkedUser(p.ID, c.sub); ok {
		if rec, ok := o.Users.Lookup(name); ok && rec.OIDCEmail != "" {
			return name, nil
		}
		return "", fmt.Errorf("subject %q is linked to %q, who can no longer sign in this way", c.sub, name)
	}
	if !c.verified || c.email == "" {
		return "", fmt.Errorf("first sign-in for subject %q has no verified email", c.sub)
	}
	name, ok := o.Users.OIDCUsers()[strings.ToLower(c.email)]
	if !ok {
		return "", fmt.Errorf("%q is not linked to any user", c.email)
	}
	if err := o.Store.Link(p.ID, c.sub, name); err != nil {
		return "", fmt.Errorf("linking %q to %q: %w", c.sub, name, err)
	}
	log.Printf("audit: %s linked to %s account %q", name, p.Name, c.sub)
	return name, nil
}

func (o *OIDCLogin) exchange(ctx context.Context, p OIDCProvider, code string, st oauthState) (oidcClaims, error) {
	form := url.Values{"code": {code}, "client_id": {p.ClientID}, "client_secret": {p.ClientSecret},
		"redirect_uri": {p.RedirectURL}, "grant_type": {"authorization_code"}, "code_verifier": {st.Verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oidcClaims{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := o.client().Do(req) // #nosec G704 -- the token URL was discovered when an admin saved the provider
	if err != nil {
		return oidcClaims{}, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return oidcClaims{}, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return oidcClaims{}, fmt.Errorf("token endpoint answered %d", resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.IDToken == "" {
		return oidcClaims{}, errors.New("token response has no id_token")
	}
	return o.validate(p, tr.IDToken, st.Nonce)
}

// validate checks an ID token received straight from the token endpoint over
// TLS, which OpenID Connect Core §3.1.3.7 accepts in place of checking its
// signature: issuer, audience, expiry, issue time and nonce.
func (o *OIDCLogin) validate(p OIDCProvider, token, wantNonce string) (oidcClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return oidcClaims{}, errors.New("id_token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return oidcClaims{}, errors.New("id_token payload is not base64url")
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	var c rawClaims
	if err := dec.Decode(&c); err != nil {
		return oidcClaims{}, errors.New("id_token payload is not JSON")
	}
	isGoogle := p.ID == GoogleProviderID
	if isGoogle && !googleIssuers[c.Iss] {
		return oidcClaims{}, fmt.Errorf("id_token issuer %q is not Google", c.Iss)
	}
	if !isGoogle && strings.TrimRight(c.Iss, "/") != strings.TrimRight(p.Issuer, "/") {
		return oidcClaims{}, fmt.Errorf("id_token issuer %q is not %q", c.Iss, p.Issuer)
	}
	if !audienceOK(c.Aud, c.Azp, p.ClientID) {
		return oidcClaims{}, errors.New("id_token audience is not this client")
	}
	now := o.now()
	exp, err1 := c.Exp.Int64()
	iat, err2 := c.Iat.Int64()
	if err1 != nil || err2 != nil {
		return oidcClaims{}, errors.New("id_token exp/iat missing or not integers")
	}
	if now.After(time.Unix(exp, 0).Add(clockSkew)) {
		return oidcClaims{}, errors.New("id_token expired")
	}
	if time.Unix(iat, 0).After(now.Add(clockSkew)) {
		return oidcClaims{}, errors.New("id_token issued in the future")
	}
	if wantNonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(wantNonce)) != 1 {
		return oidcClaims{}, errors.New("id_token nonce does not match")
	}
	if c.Sub == "" || len(c.Sub) > 255 {
		return oidcClaims{}, errors.New("id_token has no usable subject")
	}
	out := oidcClaims{sub: c.Sub, verified: emailVerified(c.EmailVerified)}
	if e := strings.TrimSpace(c.Email); e != "" && emailPattern.MatchString(e) {
		out.email = strings.ToLower(e)
	}
	if isGoogle {
		// Google is matched by address alone, so a verified plain-ASCII one is required.
		if !out.verified {
			return oidcClaims{}, errors.New("google account email is not verified")
		}
		if out.email == "" {
			return oidcClaims{}, errors.New("id_token has no usable email (is the email scope granted?)")
		}
	}
	return out, nil
}
