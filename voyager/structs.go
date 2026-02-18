package voyager

// Pagination Types

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

// Location Types

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

// Plan Types

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

// Project Types

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

// Server Types

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

// ServerResponse represents a single server API response
type ServerResponse struct {
	Data Server `json:"data"`
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

// SSHKey represents an SSH key resource
type SSHKey struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Body string `json:"body"`
}

// SSHKeysResponse represents the API response for SSH keys
type SSHKeysResponse struct {
	Data  []SSHKey `json:"data"`
	Links Links    `json:"links"`
	Meta  Meta     `json:"meta"`
}
