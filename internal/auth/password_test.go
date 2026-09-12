package auth

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Error("VerifyPassword() = false, want true for the correct password")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Error("VerifyPassword() = true, want false for the wrong password")
	}
}

func TestVerifyPassword_MalformedHash(t *testing.T) {
	if VerifyPassword("not-a-bcrypt-hash", "anything") {
		t.Error("VerifyPassword() = true, want false for a malformed hash")
	}
}
