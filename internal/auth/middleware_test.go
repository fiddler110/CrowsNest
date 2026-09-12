package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequireSession_NoCookie(t *testing.T) {
	mgr := NewSessionManager([]byte("secret"), time.Hour)
	handler := RequireSession(mgr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run without a valid session")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireSession_ValidCookie(t *testing.T) {
	mgr := NewSessionManager([]byte("secret"), time.Hour)
	session, _ := mgr.New("scott")
	token, _ := mgr.Encode(session)

	var gotUser string
	handler := RequireSession(mgr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := FromContext(r.Context())
		if !ok {
			t.Fatal("FromContext() ok = false, want session attached")
		}
		gotUser = s.Username
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotUser != "scott" {
		t.Fatalf("session username = %q, want scott", gotUser)
	}
}

func TestRequireCSRF(t *testing.T) {
	mgr := NewSessionManager([]byte("secret"), time.Hour)
	session, _ := mgr.New("scott")
	token, _ := mgr.Encode(session)

	handler := RequireSession(mgr, RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		return req
	}

	t.Run("missing token", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, newReq())
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		req := newReq()
		req.Header.Set("X-CSRF-Token", "wrong")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("correct token", func(t *testing.T) {
		req := newReq()
		req.Header.Set("X-CSRF-Token", session.CSRFToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})
}

func TestSecurityHeaders(t *testing.T) {
	var gotNonce string
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotNonce, _ = NonceFromContext(r.Context())
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", rec.Header().Get("X-Frame-Options"))
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", rec.Header().Get("X-Content-Type-Options"))
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if gotNonce == "" {
		t.Fatal("NonceFromContext() returned empty, want a generated nonce")
	}
	if !strings.Contains(csp, gotNonce) {
		t.Errorf("CSP header %q does not contain the request's nonce %q", csp, gotNonce)
	}
}
