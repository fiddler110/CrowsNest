package auth

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	PasswordCost = 4 // bcrypt's minimum: hashing is the slow part of every test
	os.Exit(m.Run())
}
