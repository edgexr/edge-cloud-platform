package cloudflare

import (
	"fmt"
	"strings"

	log "github.com/bobbae/logrus"
	cloudflare "github.com/cloudflare/cloudflare-go"
)

var cfUser, cfAPIKey string

//API handle
var API *cloudflare.API

// InitAPI has to be called first to initialize user, domain and api key for the cloudflare API access
func InitAPI(user, apiKey string) error {
	if user == "" {
		return fmt.Errorf("missing user")
	}
	if apiKey == "" {
		return fmt.Errorf("missing apiKey")
	}

	cfUser = user
	cfAPIKey = apiKey
	return nil
}

//GetAPI returns api handle for the given user, api key. Error is returned otherwise.
func GetAPI() (*cloudflare.API, error) {
	if API != nil {
		return API, nil
	}

	if cfAPIKey == "" {
		return nil, fmt.Errorf("missing API key")
	}
	if cfUser == "" {
		return nil, fmt.Errorf("missing user")
	}

	api, err := cloudflare.New(cfAPIKey, cfUser)
	if err != nil {
		return nil, err
	}
	API = api
	return api, nil
}

//GetDNSRecords returns a list of DNS records for the given domain name. Error returned otherewise.
func GetDNSRecords(zone string) ([]cloudflare.DNSRecord, error) {
	if zone == "" {
		return nil, fmt.Errorf("missing domain zone")
	}

	api, err := GetAPI()
	if err != nil {
		return nil, err
	}

	zoneID, err := api.ZoneIDByName(zone)
	if err != nil {
		return nil, err
	}

	records, err := api.DNSRecords(zoneID, cloudflare.DNSRecord{})
	if err != nil {
		return nil, err
	}
	return records, nil
}

//CreateDNSRecord creates a new DNS record for the zone
func CreateDNSRecord(zone, name, rtype, content string, ttl int, proxy bool) error {
	if zone == "" {
		return fmt.Errorf("missing zone")
	}

	if name == "" {
		return fmt.Errorf("missing name")
	}

	if rtype == "" {
		return fmt.Errorf("missing rtype")
	}

	if content == "" {
		return fmt.Errorf("missing content")
	}

	if ttl <= 0 {
		return fmt.Errorf("invalid TTL")
	}
	//ttl = 1 // automatic

	api, err := GetAPI()
	if err != nil {
		return err
	}

	zoneID, err := api.ZoneIDByName(zone)
	if err != nil {
		return err
	}

	record := cloudflare.DNSRecord{
		Name:    name,
		Type:    strings.ToUpper(rtype),
		Content: content,
		TTL:     ttl,
		Proxied: proxy,
	}

	resp, err := api.CreateDNSRecord(zoneID, record)
	if err != nil {
		return fmt.Errorf("cannot create DNS record for zone %s, %v", zone, err)
	}

	log.Debugf("create DNS record returns response, %v", resp)

	return nil
}

//DeleteDNSRecord deletes DNS record specified by recordID in zone.
func DeleteDNSRecord(zone, recordID string) error {
	if zone == "" {
		return fmt.Errorf("missing zone")
	}

	if recordID == "" {
		return fmt.Errorf("missing recordID")
	}

	api, err := GetAPI()
	if err != nil {
		return err
	}

	zoneID, err := api.ZoneIDByName(zone)
	if err != nil {
		return err
	}

	err = api.DeleteDNSRecord(zoneID, recordID)
	if err != nil {
		return err
	}

	return nil
}
