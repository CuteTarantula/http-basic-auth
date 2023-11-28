package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tg123/go-htpasswd"
)

func TestMD5(t *testing.T) {
	password := "myPassword"
	auth := "myName:$apr1$OEG5bVcu$EjaGiVHJYUOp6cOfipyQc1"

	user := auth[:strings.IndexByte(auth, ':')]
	pass := auth[strings.IndexByte(auth, ':')+1:]

	p, err := htpasswd.AcceptMd5(pass)
	require.NoError(t, err)
	require.True(t, p.MatchesPassword(password))
	require.Equal(t, user, "myName")
}
