package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/mfa"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	hash, err := HashPassword("s3cret-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	return &Service{
		Users:        Users{"alice": {Hash: hash}},
		Sessions:     NewSessionManager([]byte("test-secret"), time.Hour),
		LoginLimiter: NewLimiter(100, time.Minute),
	}
}

func doLogin(t *testing.T, svc *Service, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(loginRequest{Username: username, Password: password})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	svc.ServeLogin(rec, req)
	return rec
}

func TestServeLogin_Success(t *testing.T) {
	svc := newTestService(t)
	rec := doLogin(t, svc, "Alice", "s3cret-password")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != SessionCookieName || cookies[0].Value == "" {
		t.Fatalf("cookies = %+v, want one non-empty %s cookie", cookies, SessionCookieName)
	}

	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.CSRFToken == "" {
		t.Fatal("response CSRF token is empty")
	}

	session, err := svc.Sessions.Decode(cookies[0].Value)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if session.Username != "alice" || session.CSRFToken != resp.CSRFToken {
		t.Fatalf("session = %+v, want username alice matching returned csrf token", session)
	}
}

func TestServeLogin_WrongPassword(t *testing.T) {
	svc := newTestService(t)
	rec := doLogin(t, svc, "alice", "wrong-password")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestServeLogin_UnknownUser(t *testing.T) {
	svc := newTestService(t)
	rec := doLogin(t, svc, "ghost", "whatever")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestServeLogin_RateLimited(t *testing.T) {
	svc := newTestService(t)
	svc.LoginLimiter = NewLimiter(1, time.Minute)

	first := doLogin(t, svc, "alice", "wrong-password")
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("first attempt status = %d, want %d", first.Code, http.StatusUnauthorized)
	}
	second := doLogin(t, svc, "alice", "s3cret-password")
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second attempt status = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
}

func TestServeLogin_BodyTooLarge(t *testing.T) {
	svc := newTestService(t)

	oversized := bytes.Repeat([]byte("a"), maxLoginBodyBytes+1)
	body, _ := json.Marshal(loginRequest{Username: "alice", Password: string(oversized)})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	svc.ServeLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d for an oversized body", rec.Code, http.StatusBadRequest)
	}
}

func TestServeLogout_ClearsCookie(t *testing.T) {
	svc := newTestService(t)
	rec := httptest.NewRecorder()
	svc.ServeLogout(rec, httptest.NewRequest(http.MethodPost, "/logout", nil))

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != SessionCookieName {
		t.Fatalf("cookies = %+v, want one %s cookie", cookies, SessionCookieName)
	}
	if cookies[0].MaxAge >= 0 {
		t.Fatalf("logout cookie MaxAge = %d, want negative (delete)", cookies[0].MaxAge)
	}
}

type fakeMFA struct {
	code     string
	enabled  bool
	attempts int
}

func (f *fakeMFA) Enabled(string) bool     { return f.enabled }
func (f *fakeMFA) RecoveryLeft(string) int { return 3 }
func (f *fakeMFA) Verify(_, code string) (bool, error) {
	f.attempts++
	if code == f.code {
		return false, nil
	}
	return false, mfa.ErrBadCode
}

func TestLoginWithSecondFactor(t *testing.T) {
	hash, _ := HashPassword("correct horse")
	svc := &Service{Users: Users{"ann": {Hash: hash}}, Sessions: NewSessionManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour)}
	svc.Sessions.Users = svc.Users
	f := &fakeMFA{code: "123456", enabled: true}
	svc.MFA = f

	post := func(h http.HandlerFunc, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	rec := post(svc.ServeLogin, `{"username":"ann","password":"correct horse"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "mfa_required") {
		t.Fatalf("password step = %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName {
			t.Fatal("a session was issued before the second factor")
		}
	}
	var pending *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == mfaCookieName {
			pending = c
		}
	}
	if pending == nil {
		t.Fatal("no pending cookie")
	}
	if rec := post(svc.ServeLoginMFA, `{"code":"123456"}`); rec.Code != 401 {
		t.Errorf("code without the pending cookie = %d, want 401", rec.Code)
	}
	if rec := post(svc.ServeLoginMFA, `{"code":"000000"}`, pending); rec.Code != 401 {
		t.Errorf("wrong code = %d, want 401", rec.Code)
	}
	rec = post(svc.ServeLoginMFA, `{"code":"123456"}`, pending)
	if rec.Code != 200 {
		t.Fatalf("right code = %d %s", rec.Code, rec.Body.String())
	}
	var got bool
	for _, c := range rec.Result().Cookies() {
		got = got || (c.Name == SessionCookieName && c.Value != "")
	}
	if !got {
		t.Error("no session after the second factor")
	}
	// A user without a second factor signs in in one step.
	f.enabled = false
	if rec := post(svc.ServeLogin, `{"username":"ann","password":"correct horse"}`); !strings.Contains(rec.Body.String(), "csrf_token") {
		t.Errorf("no-MFA login = %s", rec.Body.String())
	}
}
