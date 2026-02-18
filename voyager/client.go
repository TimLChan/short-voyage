package voyager

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Client represents a client for the Voyager API
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Token      string
}

// NewClient creates a new Voyager API client
func NewClient(baseURL, token string) *Client {
	log.WithField("component", "voyager").Info("initialising client")
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		Token: token,
	}
}

// doRequest performs the HTTP request and decodes the response
func (c *Client) doRequest(method, path string, body interface{}, result interface{}, expectedStatuses ...int) error {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	isExpected := false
	for _, status := range expectedStatuses {
		if resp.StatusCode == status {
			isExpected = true
			break
		}
	}

	if !isExpected {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// VerifyToken verifies the Voyager API token by calling the /auth endpoint
func (c *Client) VerifyToken() error {
	return c.doRequest("GET", "/auth", nil, nil, http.StatusNoContent)
}

// GetLocations retrieves all locations from the Voyager API
func (c *Client) GetLocations() ([]Location, error) {
	var resp LocationsResponse
	if err := c.doRequest("GET", "/locations", nil, &resp, http.StatusOK); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetSSHKeys retrieves all SSH keys from the account
func (c *Client) GetSSHKeys() ([]SSHKey, error) {
	var resp SSHKeysResponse
	if err := c.doRequest("GET", "/account/ssh_keys", nil, &resp, http.StatusOK); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetProjects retrieves all projects from the Voyager API
func (c *Client) GetProjects() ([]Project, error) {
	var resp ProjectsResponse
	if err := c.doRequest("GET", "/projects", nil, &resp, http.StatusOK); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// CreateProject creates a new project
func (c *Client) CreateProject(name, description string) (*Project, error) {
	log.WithField("component", "voyager").Infof("creating project %s", name)
	req := ProjectRequest{
		Name:        name,
		Description: description,
	}

	var resp ProjectResponse
	if err := c.doRequest("POST", "/projects", req, &resp, http.StatusCreated); err != nil {
		return nil, err
	}

	log.WithField("component", "voyager").Infof("created project %s", resp.Data.Name)
	return &resp.Data, nil
}

// GetProjectPlans retrieves all plans available for a specific project
func (c *Client) GetProjectPlans(projectID int) ([]Plan, error) {
	var resp PlansResponse
	if err := c.doRequest("GET", fmt.Sprintf("/projects/%d/plans", projectID), nil, &resp, http.StatusOK); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// ListServers retrieves all servers for a specific project
func (c *Client) ListServers(projectID int, projectName string) ([]Server, error) {
	log.WithField("component", "voyager").Infof("checking project '%s' for servers", projectName)

	var resp ServersResponse
	if err := c.doRequest("GET", fmt.Sprintf("/projects/%d/servers", projectID), nil, &resp, http.StatusOK); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetServer retrieves a specific server by ID
func (c *Client) GetServer(serverID int) (*Server, error) {
	var resp ServerResponse
	err := c.doRequest("GET", fmt.Sprintf("/servers/%d", serverID), nil, &resp, http.StatusOK)
	if err != nil {
		// Handle 404 specifically if needed, but doRequest returns error for non-200
		if strings.Contains(err.Error(), "status 404") {
			return nil, nil
		}
		return nil, err
	}
	return &resp.Data, nil
}

// DeleteServer deletes a server by its ID
func (c *Client) DeleteServer(serverID int) error {
	log.WithField("component", "voyager").Infof("deleting server %d", serverID)
	// Delete can return 200 or 204
	return c.doRequest("DELETE", fmt.Sprintf("/servers/%d", serverID), nil, nil, http.StatusNoContent, http.StatusOK)
}

// CreateServer creates a new server under a project
func (c *Client) CreateServer(projectID int, req CreateServerRequest) (*Server, error) {
	log.WithField("component", "voyager").Infof("creating server %s", req.Name)

	var resp ServerResponse
	if err := c.doRequest("POST", fmt.Sprintf("/projects/%d/servers", projectID), req, &resp, http.StatusCreated); err != nil {
		return nil, err
	}

	log.WithField("component", "voyager").Infof("server %s created successfully with ID %d", resp.Data.Name, resp.Data.ID)
	return &resp.Data, nil
}
