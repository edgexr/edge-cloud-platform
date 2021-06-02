package orm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidName(t *testing.T) {
	var err error

	var NameMax90Chars = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"

	gname := GitlabGroupSanitize("atlantic, inc.")
	require.Equal(t, "atlantic--inc", gname)

	err = ValidName(".orgname_123.dev")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("-orgname_123.dev")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("orgname_123.dev.")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("orgname_123dev-cache")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("orgname_123dev.git")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("orgname_123dev.atom")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("orgname_123dev test")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("orgname_123dev,test")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("username_123dev::test")
	require.NotNil(t, err, "invalid user name")

	err = ValidName("username_123dev&test")
	require.NotNil(t, err, "invalid user name")

	err = ValidName(NameMax90Chars + "1")
	require.NotNil(t, err, "invalid org name")

	err = ValidName(NameMax90Chars)
	require.Nil(t, err)

}
