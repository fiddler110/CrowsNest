package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/skip2/go-qrcode"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/history"
	"github.com/fiddler110/crowsnest/internal/mfa"
)

// totpIssuer is the name authenticator apps show for the account.
const totpIssuer = "CrowsNest"

func (a *App) handleAccountPage(w http.ResponseWriter, r *http.Request) {
	session, _ := auth.FromContext(r.Context())
	data := dashboardData{Page: "account", Username: session.Username,
		IsAdmin:   a.Auth.Sessions.RoleFor(session.Username) == auth.RoleAdmin,
		CSRFToken: session.CSRFToken}
	data.NeedsPassword = data.IsAdmin && !a.Auth.HasPassword(session.Username)
	render(w, a.Templates.Account, data, "account page")
}

type securityView struct {
	HasPassword  bool `json:"has_password"`
	TOTPAvail    bool `json:"totp_available"`
	TOTPEnabled  bool `json:"totp_enabled"`
	Pending      bool `json:"totp_pending"`
	RecoveryLeft int  `json:"recovery_left"`
}

func (a *App) securityView(user string) securityView {
	v := securityView{HasPassword: a.Auth.HasPassword(user), TOTPAvail: a.MFA != nil}
	if a.MFA != nil {
		v.TOTPEnabled = a.MFA.Enabled(user)
		_, v.Pending = a.MFA.PendingSecret(user)
		v.RecoveryLeft = a.MFA.RecoveryLeft(user)
	}
	return v
}

func (a *App) mfaOn(w http.ResponseWriter, r *http.Request) bool {
	if a.MFA == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (a *App) handleGetSecurity(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.securityView(actor(r)))
}

type mfaBody struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func readMFABody(w http.ResponseWriter, r *http.Request) (mfaBody, bool) {
	var b mfaBody
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return b, false
	}
	return b, true
}

func (a *App) recordUser(r *http.Request, detail string) {
	if a.History != nil {
		a.History.Record(history.KindUsers, "", actor(r), detail)
	}
}

// mfaFailure answers a store error without saying more than the user needs.
func mfaFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, mfa.ErrLocked):
		http.Error(w, "too many wrong codes, try again in a few minutes", http.StatusTooManyRequests)
	case errors.Is(err, mfa.ErrBadCode):
		http.Error(w, "that code is not right", http.StatusForbidden)
	default:
		http.Error(w, "could not do that", http.StatusBadRequest)
	}
}

// handleTOTPBegin starts enrolment. The password is asked again, and only an
// account that signs in with one can enrol: the code is asked after a
// password, so for a Google-only account it would never be used.
func (a *App) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	if !a.mfaOn(w, r) {
		return
	}
	b, ok := readMFABody(w, r)
	if !ok {
		return
	}
	user := actor(r)
	if !a.Auth.HasPassword(user) {
		http.Error(w, "an authenticator app protects password sign-in; set a password for your account first (people who sign in with Google use Google's own protections)", http.StatusBadRequest)
		return
	}
	if !a.confirmSelf(w, r, b.Password) {
		return
	}
	secret, err := a.MFA.Begin(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "uri": mfa.URI(totpIssuer, user, secret)})
}

// handleTOTPQR draws the pending enrolment's QR code. It carries the secret,
// so it is for the signed-in user only and never cached.
func (a *App) handleTOTPQR(w http.ResponseWriter, r *http.Request) {
	if !a.mfaOn(w, r) {
		return
	}
	user := actor(r)
	secret, ok := a.MFA.PendingSecret(user)
	if !ok {
		http.NotFound(w, r)
		return
	}
	png, err := qrcode.Encode(mfa.URI(totpIssuer, user, secret), qrcode.Medium, 224)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// handleTOTPConfirm finishes enrolment with the first code and returns the
// recovery codes, shown once.
func (a *App) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	if !a.mfaOn(w, r) {
		return
	}
	b, ok := readMFABody(w, r)
	if !ok {
		return
	}
	codes, err := a.MFA.Confirm(actor(r), b.Code)
	if err != nil {
		mfaFailure(w, err)
		return
	}
	a.recordUser(r, "turned on an authenticator app for "+actor(r))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// handleTOTPDisable removes the second factor. It asks for the password and a
// current code (or a recovery code), so a stolen session alone can't do it.
func (a *App) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if !a.mfaOn(w, r) {
		return
	}
	b, ok := readMFABody(w, r)
	if !ok {
		return
	}
	user := actor(r)
	if !a.confirmSelf(w, r, b.Password) {
		return
	}
	if a.MFA.Enabled(user) {
		if _, err := a.MFA.Verify(user, b.Code); err != nil {
			mfaFailure(w, err)
			return
		}
	}
	if err := a.MFA.Remove(user); err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	a.recordUser(r, "turned off the authenticator app for "+user)
	writeJSON(w, http.StatusOK, a.securityView(user))
}

// handleTOTPRecovery replaces the recovery codes (password and a current code).
func (a *App) handleTOTPRecovery(w http.ResponseWriter, r *http.Request) {
	if !a.mfaOn(w, r) {
		return
	}
	b, ok := readMFABody(w, r)
	if !ok {
		return
	}
	user := actor(r)
	if !a.confirmSelf(w, r, b.Password) {
		return
	}
	if _, err := a.MFA.Verify(user, b.Code); err != nil {
		mfaFailure(w, err)
		return
	}
	codes, err := a.MFA.NewRecoveryCodes(user)
	if err != nil {
		mfaFailure(w, err)
		return
	}
	a.recordUser(r, "made new recovery codes for "+user)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// confirmSelf checks the signed-in user's own password again.
func (a *App) confirmSelf(w http.ResponseWriter, r *http.Request, password string) bool {
	ok, have, limited := a.Auth.ConfirmPassword(r, actor(r), password)
	switch {
	case !have:
		http.Error(w, "set a password for your account first", http.StatusForbidden)
	case limited:
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
	case !ok:
		http.Error(w, "that password is not right", http.StatusForbidden)
	default:
		return true
	}
	return false
}

// resetMFA is an admin removing a user's second factor (a lost phone). It
// ends their sessions too.
func (a *App) resetMFA(name string) error {
	if a.MFA == nil {
		return errors.New("authenticator apps are not available on this server")
	}
	if !a.MFA.Enabled(name) {
		if _, pending := a.MFA.PendingSecret(name); !pending {
			return errors.New("that user has no authenticator app")
		}
	}
	return a.MFA.Remove(strings.ToLower(name))
}
