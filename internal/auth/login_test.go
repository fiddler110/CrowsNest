package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	hash, err := HashPassword("s3cret-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	return &Service{
		Users:        Users{"scott": hash},
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
	rec := doLogin(t, svc, "Scott", "s3cret-password")

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
	if session.Username != "scott" || session.CSRFToken != resp.CSRFToken {
		t.Fatalf("session = %+v, want username scott matching returned csrf token", session)
	}
}

func TestServeLogin_WrongPassword(t *testing.T) {
	svc := newTestService(t)
	rec := doLogin(t, svc, "scott", "wrong-password")
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

	first := doLogin(t, svc, "scott", "wrong-password")
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("first attempt status = %d, want %d", first.Code, http.StatusUnauthorized)
	}
	second := doLogin(t, svc, "scott", "s3cret-password")
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second attempt status = %d, want %d", second.Code, http.StatusTooManyRequests)
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
