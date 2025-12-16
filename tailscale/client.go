package tailscale

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Client represents a client for the Tailscale API
type Client struct {
	BaseURL      string
	HTTPClient   *http.Client
	ClientID     string
	ClientSecret string
	Tailnet      string
	Token        string
}

// NewClient creates a new Tailscale API client
func NewClient(baseURL, clientID, clientSecret, tailnet string) *Client {
	log.WithField("component", "tailscale").Info("creating client")
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Tailnet:      tailnet,
	}
}

// doRequest performs the HTTP request and decodes the response
func (c *Client) doRequest(method, path string, body interface{}, result interface{}, expectedStatus int) error {
	var reqBody io.Reader
	if body != nil {
		if v, ok := body.(url.Values); ok {
			reqBody = strings.NewReader(v.Encode())
		} else {
			jsonBody, err := json.Marshal(body)
			if err != nil {
				return fmt.Errorf("failed to marshal request body: %w", err)
			}
			reqBody = bytes.NewBuffer(jsonBody)
		}
	}

	req, err := http.NewRequest(method, c.BaseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		if _, ok := body.(url.Values); ok {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != expectedStatus {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// TokenResponse represents the OAuth token response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// GetAccessToken obtains an OAuth access token using client credentials
func (c *Client) GetAccessToken() error {
	data := url.Values{}
	data.Set("client_id", c.ClientID)
	data.Set("client_secret", c.ClientSecret)
	data.Set("grant_type", "client_credentials")

	var tokenResp TokenResponse

	if err := c.doRequest("POST", "/oauth/token", data, &tokenResp, http.StatusOK); err != nil {
		return err
	}

	c.Token = tokenResp.AccessToken
	log.WithField("component", "tailscale").Info("authenticated with tailscale")
	return nil
}

// ValidateToken validates the current token by making a lightweight API call to the keys endpoint
func (c *Client) ValidateToken() error {
	if c.Token == "" {
		return fmt.Errorf("no token available")
	}

	return c.doRequest("GET", fmt.Sprintf("/tailnet/%s/keys", c.Tailnet), nil, nil, http.StatusOK)
}

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

// CreateKey creates a new auth key with the specified tags
func (c *Client) CreateKey(tags []string) (*KeyResponse, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("no token available")
	}

	keyReq := CreateKeyRequest{
		ExpirySeconds: 86400 * 90, // 90 days
		Description:   "Created by short-voyage",
	}

	keyReq.Capabilities.Devices.Create.Reusable = false
	keyReq.Capabilities.Devices.Create.Ephemeral = true
	keyReq.Capabilities.Devices.Create.Preauthorized = true

	// Ensure tags are properly formatted (must start with "tag:")
	formattedTags := make([]string, len(tags))
	for i, tag := range tags {
		if !strings.HasPrefix(tag, "tag:") {
			formattedTags[i] = "tag:" + tag
		} else {
			formattedTags[i] = tag
		}
	}
	keyReq.Capabilities.Devices.Create.Tags = formattedTags

	var keyResp KeyResponse
	if err := c.doRequest("POST", fmt.Sprintf("/tailnet/%s/keys", c.Tailnet), keyReq, &keyResp, http.StatusOK); err != nil {
		return nil, err
	}

	log.WithField("component", "tailscale").Infof("authkey created with id: %s", keyResp.ID)
	return &keyResp, nil
}
