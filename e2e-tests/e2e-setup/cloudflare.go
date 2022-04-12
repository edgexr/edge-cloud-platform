// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e2esetup

import (
	"fmt"
	"log"
	"os"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go"
)

func getCloudflareUserAndKey() (string, string) {
	user := os.Getenv("MEX_CF_USER")
	apikey := os.Getenv("MEX_CF_KEY")
	return user, apikey
}

func CreateCloudflareRecords() error {
	log.Printf("createCloudflareRecords\n")

	ttl := 300
	if Deployment.Cloudflare.Zone == "" {
		return nil
	}
	user, apiKey := getCloudflareUserAndKey()
	if user == "" || apiKey == "" {
		log.Printf("Unable to get Cloudflare settings\n")
		return fmt.Errorf("need to set MEX_CF_USER and MEX_CF_KEY for cloudflare")
	}

	api, err := cloudflare.New(apiKey, user)
	if err != nil {
		log.Printf("Error in getting Cloudflare API %v\n", err)
		return err
	}
	zoneID, err := api.ZoneIDByName(Deployment.Cloudflare.Zone)
	if err != nil {
		log.Printf("Cloudflare zone error: %v\n", err)
		return err
	}
	for _, r := range Deployment.Cloudflare.Records {
		log.Printf("adding dns entry: %s content: %s \n", r.Name, r.Content)

		addRecord := cloudflare.DNSRecord{
			Name:    strings.ToLower(r.Name),
			Type:    strings.ToUpper(r.Type),
			Content: r.Content,
			TTL:     ttl,
			Proxied: false,
		}
		queryRecord := cloudflare.DNSRecord{
			Name:    strings.ToLower(r.Name),
			Type:    strings.ToUpper(r.Type),
			Proxied: false,
		}

		records, err := api.DNSRecords(zoneID, queryRecord)
		if err != nil {
			log.Printf("Error querying dns %s, %v", zoneID, err)
			return err
		}
		for _, r := range records {
			log.Printf("Found a DNS record to delete %v\n", r)
			//we could try updating instead, but that is problematic if there
			//are multiple.  We are going to add it back anyway
			err := api.DeleteDNSRecord(zoneID, r.ID)
			if err != nil {
				log.Printf("Error in deleting DNS record for %s - %v\n", r.Name, err)
				return err
			}
		}

		resp, err := api.CreateDNSRecord(zoneID, addRecord)
		if err != nil {
			log.Printf("Error, cannot create DNS record for zone %s, %v", zoneID, err)
			return err
		}
		log.Printf("Cloudflare Create DNS Response %+v\n", resp)

	}
	return nil
}

//delete provioned records from DNS
func DeleteCloudfareRecords() error {
	log.Printf("deleteCloudfareRecords\n")

	if Deployment.Cloudflare.Zone == "" {
		return nil
	}
	user, apiKey := getCloudflareUserAndKey()
	if user == "" || apiKey == "" {
		log.Printf("Unable to get Cloudflare settings\n")
		return fmt.Errorf("need to set CF_USER and CF_KEY for cloudflare")
	}
	api, err := cloudflare.New(apiKey, user)
	if err != nil {
		log.Printf("Error in getting Cloudflare API %v\n", err)
		return err
	}
	zoneID, err := api.ZoneIDByName(Deployment.Cloudflare.Zone)
	if err != nil {
		log.Printf("Cloudflare zone error: %v\n", err)
		return err
	}

	//make a hash of the records we are looking for so we don't have to iterate thru the
	//list many times
	recordsToClean := make(map[string]bool)
	for _, d := range Deployment.Cloudflare.Records {
		//	recordsToClean[strings.ToLower(d.Name+d.Type+d.Content)] = true
		//delete records with the same name even if they point to a different ip
		recordsToClean[strings.ToLower(d.Name+d.Type)] = true
		log.Printf("cloudflare recordsToClean: %v", d.Name+d.Type)
	}

	//find all the records for the zone and delete ours.  Alternately we could apply a filter when doing the query
	//but there could be multiple records and building that filter could be hard
	records, err := api.DNSRecords(zoneID, cloudflare.DNSRecord{})
	for _, r := range records {
		_, exists := recordsToClean[strings.ToLower(r.Name+r.Type)]
		if exists {
			log.Printf("Found a DNS record to delete %v\n", r)
			err := api.DeleteDNSRecord(zoneID, r.ID)
			if err != nil {
				log.Printf("Error in deleting DNS record for %s - %v\n", r.Name, err)
				return err
			}
		}
	}

	return nil
}
