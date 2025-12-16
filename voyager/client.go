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

// Location represents a Voyager location
type Location struct {
	ID             int         `json:"id"`
	Name           string      `json:"name"`
	Description    string      `json:"description"`
	Icon           *Icon       `json:"icon"`
	IsDefault      bool        `json:"is_default"`
	IsVisible      bool        `json:"is_visible"`
	Position       float64     `json:"position"`
	AvailablePlans []ShortPlan `json:"available_plans"`
}

// Icon represents a location icon
type Icon struct {
	ID   int    `json:"id"`
	URL  string `json:"url"`
	Name string `json:"name"`
}

// ShortPlan represents a short plan resource
type ShortPlan struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// LocationsResponse represents the API response for locations
type LocationsResponse struct {
	Data  []Location `json:"data"`
	Links Links      `json:"links"`
	Meta  Meta       `json:"meta"`
}

// Links represents pagination links
type Links struct {
	First string `json:"first"`
	Last  string `json:"last"`
	Prev  string `json:"prev"`
	Next  string `json:"next"`
}

// Meta represents pagination metadata
type Meta struct {
	CurrentPage int `json:"current_page"`
	From        int `json:"from"`
	LastPage    int `json:"last_page"`
	PerPage     int `json:"per_page"`
	To          int `json:"to"`
	Total       int `json:"total"`
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

// ShortOsImageVersion represents a short OS image version resource
type ShortOsImageVersion struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Plan represents a Voyager plan
type Plan struct {
	ID                       int                   `json:"id"`
	Name                     string                `json:"name"`
	VirtualizationType       string                `json:"virtualization_type"`
	StorageType              string                `json:"storage_type"`
	Params                   PlanData              `json:"params"`
	AvailableLocations       []Location            `json:"available_locations"`
	AvailableOSImageVersions []ShortOsImageVersion `json:"available_os_image_versions"`
	TokensPerHour            int                   `json:"tokens_per_hour"`
	TokensPerMonth           int                   `json:"tokens_per_month"`
}

// PlanData represents plan parameters
type PlanData struct {
	CPU       int     `json:"vcpu"`
	Memory    int     `json:"ram"`
	Disk      int     `json:"disk"`
	Bandwidth int     `json:"bandwidth"`
	Price     float64 `json:"price"`
}

// PlansResponse represents the API response for plans
type PlansResponse struct {
	Data  []Plan `json:"data"`
	Links Links  `json:"links"`
	Meta  Meta   `json:"meta"`
}

// Project represents a Voyager project
type Project struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsDefault   bool   `json:"is_default"`
	IsOwner     bool   `json:"is_owner"`
	Owner       User   `json:"owner"`
	Members     int    `json:"members"`
	Servers     int    `json:"servers"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// User represents a user resource
type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// ProjectsResponse represents the API response for projects
type ProjectsResponse struct {
	Data  []Project `json:"data"`
	Links Links     `json:"links"`
	Meta  Meta      `json:"meta"`
}

// ProjectRequest represents a project creation request
type ProjectRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// ProjectResponse represents a single project API response
type ProjectResponse struct {
	Data Project `json:"data"`
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

// Server represents a Voyager server (ComputeResourceVm)
type Server struct {
	ID          int         `json:"id"`
	Name        string      `json:"name"`
	Hostname    string      `json:"hostname"`
	Status      string      `json:"status"`
	PlanID      int         `json:"plan_id"`
	RegionID    int         `json:"region_id"`
	IPAddresses IPAddresses `json:"ip_addresses"`
}

// IPAddresses represents the IP addresses of a server
type IPAddresses struct {
	IPv4 []IPv4Address `json:"ipv4"`
	IPv6 []IPv6Address `json:"ipv6"`
}

// IPv4Address represents an IPv4 address
type IPv4Address struct {
	ID        int    `json:"id"`
	IP        string `json:"ip"`
	IsPrimary bool   `json:"is_primary"`
	Gateway   string `json:"gateway"`
	Netmask   string `json:"netmask"`
	CIDR      string `json:"cidr"`
}

// IPv6Address represents an IPv6 address
type IPv6Address struct {
	ID        int    `json:"id"`
	Range     string `json:"range"`
	PrimaryIP string `json:"primary_ip"`
	IsPrimary bool   `json:"is_primary"`
	Gateway   string `json:"gateway"`
}

// ServersResponse represents the API response for servers
type ServersResponse struct {
	Data  []Server `json:"data"`
	Links Links    `json:"links"`
	Meta  Meta     `json:"meta"`
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

// ServerResponse represents a single server API response
type ServerResponse struct {
	Data Server `json:"data"`
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

// BackupSettings represents backup settings for a server
type BackupSettings struct {
	Enabled bool `json:"enabled"`
}

// CreateServerRequest represents a server creation request
type CreateServerRequest struct {
	Name                      string          `json:"name"`
	LocationID                int             `json:"location_id"`
	PlanID                    int             `json:"plan_id"`
	SSHKeys                   []int           `json:"ssh_keys"`
	BackupSettings            *BackupSettings `json:"backup_settings,omitempty"`
	IPTypes                   []string        `json:"ip_types"`
	IsDisasterRecoveryEnabled bool            `json:"is_disaster_recovery_enabled"`
	OSImageVersionID          int             `json:"os_image_version_id"`
	UserData                  string          `json:"user_data"`
	FQDNs                     []string        `json:"fqdns"`
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
