# Federation

- [The Federation EWBI Readme](../../../doc/fedapi/README.md) describes the Federation EWBI APIs and server stubs.
- MC North-bound Federation APIs (of our own design) are implemented in [pkg/mc/orm/federation_mc.go](../orm/federation_mc.go)
- EWBI (East-West Bound Interface) APIs are implemented here.

## Terminology

- The GSMA spec defines a Federation as established between two *Operators*, an *Originating* Operator and a *Partner* Operator. On our platform, an *Operator* corresponds to an operator-type Organization.
- We use the term *Consumer* instead of *Originator*, and *Provider* instead of *Partner*, for better clarity.
- NB MC APIs have path prefix `/api/v1/`
- EWBI APIs have path prefix `/operatorplatform/federation/v1`

## Federation Setup

This establishes a unidirectional federation whereby a *Provider* provides edge resources to a *Consumer*, allowing the *Consumer* to deploy applications on those edge resources.

1. Operator1 creates ProviderZoneBases, to map cloudlets to zones. These definitions are federation independent. `/api/v1/auth/federation/provider/zonebase/create`
2. Operator1 creates a FederationProvider. This returns the authentication credentials to give to the consumer out of band. `/api/v1/auth/federation/provider/create`
3. (Optional) Operator1 shares ProviderZoneBases with the FederationProvider. This makes those zones available via that provider (can be done later as well) `/api/v1/auth/federation/provider/zone/share`
4. Operator2 creates a FederationConsumer, given the address and authentication credentials for a FederationProvider. This connects to the provider via the EWBI, and receives any shared provider zones, creating consumer zones for them. Optionally, it auto-registers those zones. For registered zones, it creates a Cloudlet in the configurated region to represent that zone. `/api/v1/auth/federation/consumer/create` -> `/operatorplatform/federation/v1/partner`
5. (Optional) Operator2 (consumer) will receive (via partner callback) notification of any new shared zones from Operator1 (provider). These zones can be registered. `/api/v1/auth/federation/consumer/zone/register` -> `/operatorplatform/federation/v1/{fedctxid}/zones`

Notes:
- Federations are 1-to-1.
- To establish another federation, Operator1 would need to start again with step 2.
- To establish the reverse direction, all steps would need to be repeated with the operator roles swapped.

## Controller Regions

- FederationProvider is multi-region
   - Cloudlets can be shared as zones from regions configured on the FederationProvider
   - App definitions sent by the Consumer to the Provider will be created on every region configured on the Provider
- FederationConsumer is single region
   - Cloudlets that are created on the consumer to represent Provider Zones are created in the single region configured on the FederationConsumer

## Authentication

- Authentication uses the [oauth2 client credential flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow).
- This exactly matches our user api-keys, so they are used as the auth credentials
- Consumer -> Provider uses one set of credentials and the Provider's oauth2 token server
- Provider -> Consumer callbacks use another set of credentials and the Consumer's oauth2 token server
- Clients [store the api-key in Vault](../../federationmgmt/federation.go)
- Clients use a [tokenSource](../../federationmgmt/client.go) to cache tokens (tokens are JWT)
- Oauth2 [server code](../orm/oauth2server.go) leverages existing code for validating keys and generating JWTs
- Servers [store only the hashed version](../ormutil/auth.go) of the api key password in postgres
