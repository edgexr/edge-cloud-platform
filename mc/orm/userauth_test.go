package orm

import (
	"testing"

	"github.com/nbutton23/zxcvbn-go"
	"github.com/stretchr/testify/require"
)

func TestPassword(t *testing.T) {
	testpassword(t, "somerandompassword", "instant")
	testpassword(t, "mexadmin123", "instant")
	testpassword(t, "mexadmin123456789", "3.0 minutes")
	testpassword(t, "1orangefoxquickhandlebrush1", "2.0 years")
	testpassword(t, "yzdF8!aw", "2.0 years")
	testpassword(t, "mexadminfastedgecloudinfra", "centuries")
	testpassword(t, "thequickbrownfoxjumpedoverthelazydog9$", "centuries")
}

func testpassword(t *testing.T, pw, cracktime string) {
	score := zxcvbn.PasswordStrength(pw, []string{})
	require.Equal(t, cracktime, score.CrackTimeDisplay)
}
