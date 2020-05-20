package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go"
)

var (
	delete       *bool
	matchPattern *string
	zoneName     *string
	recordsFound []cloudflare.DNSRecord
	api          *cloudflare.API
	zoneID       string
)

func printUsage() {
	fmt.Println("\nUsage: dnsaudit --match <regexp> [--delete]")
	fmt.Println("   options: ")
	fmt.Println("   --match -- regexp to filter records, e.g. \"facedetect.*automation\"")
	fmt.Println("              select \".*\" to match all ")
	fmt.Println("   --delete -- delete the matching records. Use with care.")
	fmt.Println("   --zonename  cloudflare zone (defaults to mobiledgex.net).")
}

func init() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	delete = flag.Bool("delete", false, "delete matching records, must be used with --match.  Use double escapes for regex")
	matchPattern = flag.String("match", "", "matching regexp pattern")
	zoneName = flag.String("zonename", "mobiledgex.net", "cloudflare zone (defaulst to mobiledgex.net")

	user, apiKey := getCloudflareUserAndKey()
	if user == "" || apiKey == "" {
		fmt.Println("Unable to get Cloudflare settings")
		fmt.Println("need to set MEX_CF_USER and MEX_CF_KEY for cloudflare")
		os.Exit(1)
	}

	var err error
	api, err = cloudflare.New(apiKey, user)
	if err != nil {
		fmt.Printf("unable to init cloudflare api: %v", err)
		os.Exit(1)
	}
	flag.Parse()
}

func getCloudflareUserAndKey() (string, string) {
	user := os.Getenv("MEX_CF_USER")
	apikey := os.Getenv("MEX_CF_KEY")
	return user, apikey
}

func doAudit() error {
	user, apiKey := getCloudflareUserAndKey()
	if user == "" || apiKey == "" {
		fmt.Println("Unable to get Cloudflare settings")
		fmt.Println("Need to set MEX_CF_USER and MEX_CF_KEY for cloudflare")
		os.Exit(1)
	}

	reg, err := regexp.Compile(*matchPattern)

	if err != nil {
		fmt.Printf("invalid regexp match pattern: %v", err)
		os.Exit(1)
	}
	zoneID, err = api.ZoneIDByName(*zoneName)
	if err != nil {
		fmt.Printf("Cloudflare zone error: %v\n", err)
		return err
	}
	//find all the records for the zone and delete ours optionally if it matches.
	records, err := api.DNSRecords(zoneID, cloudflare.DNSRecord{Type: "A"})
	for _, r := range records {
		if reg.MatchString(r.Name) {
			recordsFound = append(recordsFound, r)
		}
	}
	return nil
}

func deleteRecords() error {
	for _, r := range recordsFound {
		fmt.Printf("DELETING: %s\n", r.Name)
		err := api.DeleteDNSRecord(zoneID, r.ID)
		if err != nil {
			fmt.Printf("Error in deleting DNS record for %s - %v\n", r.Name, err)
			return err
		}
	}
	return nil
}

func printRecords() {
	fmt.Printf("\nRecords Matched:\n----------------\n")
	for _, r := range recordsFound {
		fmt.Printf("%s - %s\n", r.Name, r.Content)
	}
	fmt.Printf("Total Records Matched: %d\n", len(recordsFound))
}

func main() {
	if *matchPattern == "" {
		fmt.Println("ERROR: --match option required")
		printUsage()
		os.Exit(1)
	}
	if len(*matchPattern) < 5 && *delete {
		//deleting everthing is not allowed
		fmt.Println("ERROR: Cannot do --delete with a short match pattern, specify at least 5 chars")
		printUsage()
		os.Exit(1)
	}
	err := doAudit()
	if err != nil {
		fmt.Printf("audit returns error %v", err)
	}
	printRecords()
	if *delete {
		if len(recordsFound) == 0 {
			fmt.Println("nothing matched to delete")
		} else {
			answer := ""
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("\nAre you sure you want to DELETE these %d DNS records (yes/no)\n", len(recordsFound))
			answer, _ = reader.ReadString('\n')
			answer = strings.TrimSpace(answer)
			if strings.ToLower(answer) == "yes" {
				err = deleteRecords()
				if err != nil {
					fmt.Printf("error occurred in deleteRecords %v\n", err)
				}
			} else {
				fmt.Println("delete aborted")
			}
		}

	}
}
