package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/fiddler110/crowsnest/internal/auth"
)

func (a *App) passkeysOn(w http.ResponseWriter, r *http.Request) bool {
	if a.Auth.Passkeys == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (a *App) handleListPasskeys(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysOn(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": a.Auth.Passkeys.Store.List(actor(r))})
}

// handlePasskeyBegin starts adding a passkey. The password is asked again: a stolen session alone must not be able
// to plant a way back in that outlives it.
func (a *App) handlePasskeyBegin(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysOn(w, r) {
		return
	}
	b, ok := readMFABody(w, r)
	if !ok {
		return
	}
	if !a.confirmSelf(w, r, b.Password) {
		return
	}
	if err := a.Auth.PasskeyRegisterBegin(w, actor(r)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// handlePasskeyFinish takes the browser's answer; the name is in the query because the body is the credential.
func (a *App) handlePasskeyFinish(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysOn(w, r) {
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "Passkey"
	}
	if utf8.RuneCountInString(name) > 40 || strings.ContainsAny(name, "\r\n\x00") {
		http.Error(w, "a passkey's name is at most 40 characters on one line", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := a.Auth.PasskeyRegisterFinish(w, r, actor(r), name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.recordUser(r, "added a passkey")
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": a.Auth.Passkeys.Store.List(actor(r))})
}

func (a *App) handleRemovePasskey(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysOn(w, r) {
		return
	}
	var b struct {
		ID       string `json:"id"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !a.confirmSelf(w, r, b.Password) {
		return
	}
	if err := a.Auth.Passkeys.Store.Remove(actor(r), b.ID); err != nil {
		if err == auth.ErrNoPasskey {
			http.Error(w, "no such passkey", http.StatusNotFound)
			return
		}
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	a.recordUser(r, "removed a passkey")
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": a.Auth.Passkeys.Store.List(actor(r))})
}
