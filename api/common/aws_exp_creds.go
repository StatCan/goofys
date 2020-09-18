package common

import (
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"gopkg.in/ini.v1"
)

// SharedCredsProviderName provides a name of SharedCreds provider
const ExpiringSharedCredsProviderName = "ExpiringSharedCredentialsProvider"

// An ExpiringSharedCredentialsProvider retrieves access key pair (access key ID,
// secret access key, and session token if present) credentials from the current
// user's home directory, and keeps track if those credentials are expired.
//
// Profile ini file example: $HOME/.aws/credentials
type ExpiringSharedCredentialsProvider struct {
	credentials.SharedCredentialsProvider

	Expiry time.Time
}

// NewExpiringSharedCredentials returns a pointer to a new Credentials object
// wrapping the Profile file provider.
func NewExpiringSharedCredentials(filename, profile string) *credentials.Credentials {
	return credentials.NewCredentials(&ExpiringSharedCredentialsProvider{
		SharedCredentialsProvider: credentials.SharedCredentialsProvider{
			Filename: filename,
			Profile:  profile,
		},
	})
}

// Retrieve reads and extracts the shared credentials from the current
// users home directory.
func (p *ExpiringSharedCredentialsProvider) Retrieve() (credentials.Value, error) {
	creds, err := p.SharedCredentialsProvider.Retrieve()
	if err != nil {
		return creds, err
	}

	config, err := ini.Load(p.SharedCredentialsProvider.Filename)
	if err != nil {
		return credentials.Value{ProviderName: ExpiringSharedCredsProviderName}, awserr.New("SharedCredsLoad", "failed to load shared credentials file", err)
	}

	profile := p.profile()
	iniProfile, err := config.GetSection(profile)
	if err != nil {
		return credentials.Value{ProviderName: ExpiringSharedCredsProviderName}, awserr.New("SharedCredsLoad", "failed to get profile", nil)
	}

	k := iniProfile.Key("expires_at")
	if k != nil {
		p.Expiry, err = k.Time()
		if err != nil {
			return credentials.Value{ProviderName: ExpiringSharedCredsProviderName}, awserr.New("SharedCredsAccessKey",
				fmt.Sprintf("shared credentials %s in %s failed to parse expiry", profile, p.SharedCredentialsProvider.Filename),
				nil)
		}
	}

	return creds, nil
}

// IsExpired returns if the shared credentials have expired.
func (p *ExpiringSharedCredentialsProvider) IsExpired() bool {
	return p.SharedCredentialsProvider.IsExpired() || time.Now().After(p.Expiry)
}

// ExpiresAt returns when the credentials expire
func (p *ExpiringSharedCredentialsProvider) ExpiresAt() time.Time {
	return p.Expiry
}

// profile returns the AWS shared credentials profile.  If empty will read
// environment variable "AWS_PROFILE". If that is not set profile will
// return "default".
func (p *ExpiringSharedCredentialsProvider) profile() string {
	if p.Profile == "" {
		p.Profile = os.Getenv("AWS_PROFILE")
	}
	if p.Profile == "" {
		p.Profile = "default"
	}

	return p.Profile
}
