package auth

import "golang.org/x/crypto/bcrypt"

// PasswordCost is the bcrypt cost new hashes are made with. Hashes made at a lower cost are replaced the next time
// their owner signs in (HashNeedsUpgrade). A variable so tests can lower it.
var PasswordCost = 12

// HashPassword bcrypt-hashes a plaintext password for storage in the users
// file.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), PasswordCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// HashNeedsUpgrade reports whether hash was made at a lower cost than PasswordCost.
func HashNeedsUpgrade(hash string) bool {
	c, err := bcrypt.Cost([]byte(hash))
	return err == nil && c < PasswordCost
}

// VerifyPassword reports whether password matches a hash produced by
// HashPassword.
func VerifyPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
