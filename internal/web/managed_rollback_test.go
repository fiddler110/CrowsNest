package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/managed"
)

// Rollback on the fake always finds nothing to go back to.
func (f *fakeManaged) Rollback(string) error { return managed.ErrNoPrevious }

func TestManagedRollbackIsAdminCSRFAndConflict(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	h.App.Managed = &fakeManaged{}
	do := func(r *http.Request) int {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, r)
		return rec.Code
	}
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RoleAdmin}}
	if c := do(h.authedReq("POST", "/api/managed/games/minecraft/rollback", nil)); c != http.StatusConflict {
		t.Errorf("rollback with no previous image = %d, want 409", c)
	}
	if c := do(h.req("POST", "/api/managed/games/minecraft/rollback", nil)); c != http.StatusForbidden {
		t.Errorf("rollback without the CSRF header = %d, want 403", c)
	}
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RolePlayer}}
	if c := do(h.authedReq("POST", "/api/managed/games/minecraft/rollback", nil)); c != http.StatusForbidden {
		t.Errorf("player rollback = %d, want 403", c)
	}
}
