package cloudflare

import (
	"fmt"
	"os"
	"strings"
	"testing"

	log "github.com/bobbae/logrus"
)

var user, key, domain string

func TestInit(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	user = os.Getenv("CF_USER")
	key = os.Getenv("CF_KEY")
	domain = os.Getenv("CF_TEST_DOMAIN")

	if user == "" {
		t.Errorf("missing CF_USER environment variable")
	}
	if key == "" {
		t.Errorf("missing CF_KEY environment variable")
	}
	if domain == "" {
		t.Errorf("missing CF_TEST_DOMAIN environment variable")
	}

	if err := InitAPI(user, key); err != nil {
		t.Errorf("cannot initialize API, %v", err)
	}
}

func TestGetAPI(t *testing.T) {
	api, err := GetAPI()
	if err != nil {
		t.Errorf("cannot get API %v", err)
	}

	if api == nil {
		t.Errorf("missing api handle")
	}
}

func TestGetDNSRecords(t *testing.T) {
	recs, err := GetDNSRecords(domain)
	if err != nil {
		t.Errorf("can not get dns records for %s, %v", domain, err)
	}

	for _, rec := range recs {
		fmt.Println(rec)
	}
}

func TestCreateDNSRecord(t *testing.T) {
	cname := "name-test-1"
	err := CreateDNSRecord(domain, cname, "cname", domain, 1, false)
	if err != nil {
		t.Errorf("cannot create DNS record, %v", err)
	}

	//try to recreate -- should produce error
	err = CreateDNSRecord(domain, cname, "cname", domain, 1, false)
	if err == nil {
		t.Errorf("should have failed")
	}

	recs, err := GetDNSRecords(domain)
	if err != nil {
		t.Errorf("can not get dns records for %s, %v", domain, err)
	}

	for _, rec := range recs {
		if strings.HasPrefix(rec.Name, cname) {
			err = DeleteDNSRecord(domain, rec.ID)
			if err != nil {
				t.Errorf("cannot delete dns record id %s zone %s, %v", rec.ID, domain, err)
			}
		}
	}
}
