package cloudflare

import (
	"context"
	"fmt"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/mobiledgex/edge-cloud/log"
)

var LocalTestZone = "localtest.net"
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
// if name is provided, that is used as a filter
func GetDNSRecords(ctx context.Context, zone string, name string) ([]cloudflare.DNSRecord, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetDNSRecords", "name", name)

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

	queryRecord := cloudflare.DNSRecord{}
	if name != "" {
		queryRecord.Name = name
	}

	records, err := api.DNSRecords(zoneID, queryRecord)
	if err != nil {
		return nil, err
	}
	return records, nil
}

//CreateOrUpdateDNSRecord changes the existing record if found, or adds a new one
func CreateOrUpdateDNSRecord(ctx context.Context, zone, name, rtype, content string, ttl int, proxy bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateOrUpdateDNSRecord", "zone", zone, "name", name, "content", content)

	if zone == LocalTestZone {
		log.SpanLog(ctx, log.DebugLevelInfra, "Skip record creation for test zone", "zone", zone)
		return nil
	}
	api, err := GetAPI()
	if err != nil {
		return err
	}

	zoneID, err := api.ZoneIDByName(zone)
	if err != nil {
		return err
	}

	queryRecord := cloudflare.DNSRecord{
		Name: strings.ToLower(name),
		Type: strings.ToUpper(rtype),
	}
	records, err := api.DNSRecords(zoneID, queryRecord)
	if err != nil {
		return err
	}
	found := false
	for _, r := range records {
		found = true
		if r.Content == content {
			log.SpanLog(ctx, log.DebugLevelInfra, "CreateOrUpdateDNSRecord existing record matches", "name", name, "content", content)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "CreateOrUpdateDNSRecord updating", "name", name, "content", content)

			updateRecord := cloudflare.DNSRecord{
				Name:    strings.ToLower(name),
				Type:    strings.ToUpper(rtype),
				Content: content,
				TTL:     ttl,
				Proxied: proxy,
			}
			err := api.UpdateDNSRecord(zoneID, r.ID, updateRecord)
			if err != nil {
				return fmt.Errorf("cannot update DNS record for zone %s name %s, %v", zone, name, err)
			}
		}
	}
	if !found {
		addRecord := cloudflare.DNSRecord{
			Name:    strings.ToLower(name),
			Type:    strings.ToUpper(rtype),
			Content: content,
			TTL:     ttl,
			Proxied: false,
		}
		_, err := api.CreateDNSRecord(zoneID, addRecord)
		if err != nil {
			return fmt.Errorf("cannot create DNS record for zone %s, %v", zone, err)
		}
	}
	return nil
}

//CreateDNSRecord creates a new DNS record for the zone
func CreateDNSRecord(ctx context.Context, zone, name, rtype, content string, ttl int, proxy bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateDNSRecord", "name", name, "content", content)

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

	_, err = api.CreateDNSRecord(zoneID, record)
	if err != nil {
		return fmt.Errorf("cannot create DNS record for zone %s, %v", zone, err)
	}

	return nil
}

//DeleteDNSRecord deletes DNS record specified by recordID in zone.
func DeleteDNSRecord(zone, recordID string) error {
	if zone == LocalTestZone {
		return nil
	}
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

	return api.DeleteDNSRecord(zoneID, recordID)
}
