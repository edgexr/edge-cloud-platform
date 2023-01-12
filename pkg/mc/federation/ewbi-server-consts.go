package federation

// Since we're not using the api portion
// of the oapi-codegen, we need to define some
// of these path constants manually.

type FederationContextId string
type ZoneIdentifier string
type AppIdentifier string
type ArtefactId string
type FileId string
type AppProviderId string
type PoolId string
type DeviceId string
type AuthorizationToken string
type InstanceIdentifier string

const (
	OAuth2ClientCredentialsScopes = "oAuth2ClientCredentials.Scopes"
)

type CreateFederationParams struct {
	XNotifyTokenUrl *string
	XNotifyAuth     *string
}
