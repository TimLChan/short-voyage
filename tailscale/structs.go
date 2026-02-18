package tailscale

// Authentication Types

// TokenResponse represents the OAuth token response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// Key Management Types

// KeyCapabilities represents the capabilities of a key
type KeyCapabilities struct {
	Devices struct {
		Create struct {
			Reusable      bool     `json:"reusable"`
			Ephemeral     bool     `json:"ephemeral"`
			Preauthorized bool     `json:"preauthorized"`
			Tags          []string `json:"tags"`
		} `json:"create"`
	} `json:"devices"`
}

// CreateKeyRequest represents the request to create a new auth key
type CreateKeyRequest struct {
	Capabilities  KeyCapabilities `json:"capabilities"`
	ExpirySeconds int             `json:"expirySeconds"`
	Description   string          `json:"description"`
}

// KeyResponse represents the response from creating a key
type KeyResponse struct {
	ID           string          `json:"id"`
	Key          string          `json:"key"`
	Created      string          `json:"created"`
	Expires      string          `json:"expires"`
	Capabilities KeyCapabilities `json:"capabilities"`
}
