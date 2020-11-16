package orm

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustelem/zxcvbn"
)

func TestPassword(t *testing.T) {
	testpassword(t, "somerandompassword", "3.0 minutes")
	testpassword(t, "mexadmin123", "16.0 seconds")
	testpassword(t, "mexadmin123456789", "7.0 minutes")
	testpassword(t, "1orangefoxquickhandlebrush1", "centuries")
	testpassword(t, "yzdF8!aw", "3.0 minutes")
	testpassword(t, "mexadminfastedgecloudinfra", "centuries")
	testpassword(t, "thequickbrownfoxjumpedoverthelazydog9$", "centuries")
	testpassword(t, "misterx-password-supe", "6.0 months")
	testpassword(t, "oldpwd1", "5.0 seconds")
}

func testpassword(t *testing.T, pw, cracktime string) {
	result := zxcvbn.PasswordStrength(pw, []string{})
	require.Equal(t, cracktime, secDisplayTime(result.Guesses/float64(BruteForceGuessesPerSecond)))
}
