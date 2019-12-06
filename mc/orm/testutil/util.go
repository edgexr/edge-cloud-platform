package testutil

import (
	"log"
	"net/http"
)

func checkMcErr(msg string, status int, err error, rc *bool) {
	if err != nil || status != http.StatusOK {
		log.Printf("%s failed %v/%d\n", msg, err, status)
		*rc = false
	}
}
