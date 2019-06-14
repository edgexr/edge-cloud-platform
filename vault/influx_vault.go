package vault

import (
	"github.com/mitchellh/mapstructure"
	"github.com/mobiledgex/edge-cloud/vault"
)

var InfluxDBVaultPath = "https://vault.mobiledgex.net/v1/secret/data/influxdb/"

type InfluxDBVaultData struct {
	Username string
	Password string
}

// Get influxDB login credentials from the vault
func GetInfluxDBCreds(region string) (*InfluxDBVaultData, error) {
	data, err := vault.GetVaultData(InfluxDBVaultPath + "region/influxdb.json")
	if err != nil {
		return nil, err
	}
	influxData := &InfluxDBVaultData{}
	err = mapstructure.Decode(data, influxData)
	if err != nil {
		return nil, err
	}
	return influxData, nil
}
