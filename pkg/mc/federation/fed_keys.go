package federation

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	fedcommon "github.com/edgexr/edge-cloud-platform/pkg/mc/federation/common"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

func ProviderFedKey(provider *ormapi.FederationProvider) *federationmgmt.FedKey {
	return &federationmgmt.FedKey{
		OperatorId: provider.OperatorId,
		Name:       provider.Name,
		FedType:    federationmgmt.FederationTypeProvider,
		ID:         provider.ID,
	}
}

func ConsumerFedKey(consumer *ormapi.FederationConsumer) *federationmgmt.FedKey {
	return &federationmgmt.FedKey{
		OperatorId: consumer.OperatorId,
		Name:       consumer.Name,
		FedType:    federationmgmt.FederationTypeProvider,
		ID:         consumer.ID,
	}
}

func SaveProviderPartnerApiKey(ctx context.Context, provider *ormapi.FederationProvider, vaultConfig *vault.Config) error {
	if provider.PartnerNotifyClientId == "" {
		return fmt.Errorf("partner notify client id not specified")
	}
	if provider.PartnerNotifyClientKey == "" {
		return fmt.Errorf("partner notify client key not specified")
	}
	if err := fedcommon.ValidateApiKey(provider.PartnerNotifyClientKey); err != nil {
		return err
	}

	fedKey := ProviderFedKey(provider)
	apiKey := &federationmgmt.ApiKey{
		Id:       provider.PartnerNotifyClientId,
		Key:      provider.PartnerNotifyClientKey,
		TokenUrl: provider.PartnerNotifyTokenUrl,
	}
	provider.PartnerNotifyClientKey = ""

	log.SpanLog(ctx, log.DebugLevelApi, "Storing provider notify key in vault", "fedkey", fedKey)
	err := federationmgmt.PutAPIKeyToVault(ctx, vaultConfig, fedKey, apiKey)
	if err != nil {
		return err
	}
	return nil
}

func SaveConsumerPartnerApiKey(ctx context.Context, consumer *ormapi.FederationConsumer, vaultConfig *vault.Config) error {
	if consumer.ProviderClientId == "" {
		return fmt.Errorf("Provider client id not specified")
	}
	if consumer.ProviderClientKey == "" {
		return fmt.Errorf("Provider client key not specified")
	}
	if err := fedcommon.ValidateApiKey(consumer.ProviderClientKey); err != nil {
		return err
	}

	fedKey := ConsumerFedKey(consumer)
	apiKey := &federationmgmt.ApiKey{
		Id:       consumer.ProviderClientId,
		Key:      consumer.ProviderClientKey,
		TokenUrl: consumer.PartnerTokenUrl,
	}
	consumer.ProviderClientKey = ""

	log.SpanLog(ctx, log.DebugLevelApi, "Storing partner federation API key in vault", "fedkey", fedKey)
	err := federationmgmt.PutAPIKeyToVault(ctx, vaultConfig, fedKey, apiKey)
	if err != nil {
		return err
	}
	return nil
}

func DeleteProviderPartnerApiKey(ctx context.Context, provider *ormapi.FederationProvider, vaultConfig *vault.Config) error {
	fedKey := ProviderFedKey(provider)
	log.SpanLog(ctx, log.DebugLevelApi, "Delete provider partner notify key", "fedkey", fedKey)
	return federationmgmt.DeleteAPIKeyFromVault(ctx, vaultConfig, fedKey)
}

func DeleteConsumerPartnerApiKey(ctx context.Context, consumer *ormapi.FederationConsumer, vaultConfig *vault.Config) error {
	fedKey := ConsumerFedKey(consumer)
	log.SpanLog(ctx, log.DebugLevelApi, "Delete consumer partner api key", "fedkey", fedKey)
	return federationmgmt.DeleteAPIKeyFromVault(ctx, vaultConfig, fedKey)
}
