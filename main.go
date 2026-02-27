package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"short-voyage/tailscale"
	"short-voyage/voyager"

	nested "github.com/antonfisher/nested-logrus-formatter"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// generateRandomHex generates a random hex string of the specified length
func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Config represents the application configuration
type Config struct {
	Voyager struct {
		API struct {
			BaseURL string `yaml:"base_url"`
			Token   string `yaml:"token"`
		} `yaml:"api"`
		Project struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
		} `yaml:"project"`
		Server struct {
			Location        int    `yaml:"location"`
			Plan            int    `yaml:"plan"`
			OperatingSystem int    `yaml:"operatingsystem"`
			SSHKeys         []int  `yaml:"ssh_keys"`
			Fail2Ban        bool   `yaml:"fail2ban"`
			RunCmd          string `yaml:"runcmd"`
		} `yaml:"server"`
	} `yaml:"voyager"`
	Tailscale struct {
		Enabled  bool `yaml:"enabled"`
		ExitNode bool `yaml:"exit_node"`
		API      struct {
			BaseURL      string   `yaml:"base_url"`
			ClientID     string   `yaml:"clientid"`
			ClientSecret string   `yaml:"clientsecret"`
			Tailnet      string   `yaml:"tailnet"`
			Scopes       []string `yaml:"scopes"`
		} `yaml:"api"`
		Tags []string `yaml:"tags"`
	} `yaml:"tailscale"`
}

// LoadConfig loads configuration from YAML file
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)

	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

func main() {
	listFlag := flag.Bool("list", false, "List servers in the project")
	deleteFlag := flag.Bool("delete", false, "Delete a server")
	serverIDFlag := flag.Int("serverid", 0, "Server ID to delete (used with -delete)")
	createFlag := flag.Bool("create", false, "Create Tailscale auth key and generate install command")
	forceFlag := flag.Bool("force", false, "Create server without yes/no confirmation prompt (create only)")
	flag.Parse()

	log.SetFormatter(&nested.Formatter{
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
		TimestampFormat: "[2006-01-02 03:04:05 PM]",
		TrimMessages:    false,
	})

	log.WithField("component", "main").Info("starting short-voyage v0.1")

	// Load configuration
	config, err := LoadConfig("config.yaml")
	if err != nil {
		log.WithField("component", "main").Fatalf("Failed to load configuration: %v", err)
	}

	if *forceFlag && !*createFlag {
		log.WithField("component", "main").Warn("-force has no effect unless -create is also provided")
	}

	if *serverIDFlag != 0 && !*deleteFlag {
		log.WithField("component", "main").Warn("-serverid has no effect unless -delete is also provided")
	}

	if *createFlag {
		runCreateServer(config, *forceFlag)
	} else if *deleteFlag {
		runDeleteServer(config, *serverIDFlag)
	} else {
		// Default behavior or if --list is provided
		if *listFlag {
		}
		runListServers(config)
	}
}

// initVoyagerClient initialises and verifies the Voyager client
func initVoyagerClient(config *Config) *voyager.Client {
	if config.Voyager.API.Token == "" {
		log.WithField("component", "main").Fatal("Voyager token is required in config.yaml")
	}

	client := voyager.NewClient(config.Voyager.API.BaseURL, config.Voyager.API.Token)

	if err := client.VerifyToken(); err != nil {
		log.WithField("component", "main").Fatalf("Failed to verify Voyager API token: %v", err)
	}
	return client
}

// getOrCreateProject retrieves the project or creates it if it doesn't exist (and config allows)
func getOrCreateProject(client *voyager.Client, config *Config, createIfMissing bool) *voyager.Project {
	if config.Voyager.Project.Name == "" {
		log.WithField("component", "main").Fatal("No project specified in config.yaml")
	}

	projects, err := client.GetProjects()
	if err != nil {
		log.WithField("component", "main").Fatalf("Failed to get projects: %v", err)
	}

	for _, project := range projects {
		if project.Name == config.Voyager.Project.Name {
			return &project
		}
	}

	if createIfMissing {
		newProject, err := client.CreateProject(config.Voyager.Project.Name, config.Voyager.Project.Description)
		if err != nil {
			log.WithField("component", "main").Fatalf("failed to create project: %v", err)
		}
		return newProject
	}

	return nil
}

// formatServerIPs formats the server's IP addresses for display
func formatServerIPs(server voyager.Server) string {
	// Get primary IPv4 address if available
	var primaryIPv4 string
	for _, ipv4 := range server.IPAddresses.IPv4 {
		if ipv4.IsPrimary {
			primaryIPv4 = ipv4.IP
			break
		}
	}

	// Get primary IPv6 address if available
	var primaryIPv6 string
	for _, ipv6 := range server.IPAddresses.IPv6 {
		if ipv6.IsPrimary {
			primaryIPv6 = ipv6.PrimaryIP
			break
		}
	}

	// Build IP address string
	ipInfo := ""
	if primaryIPv4 != "" {
		ipInfo += primaryIPv4
	}
	if primaryIPv6 != "" {
		if ipInfo != "" {
			ipInfo += ", " + primaryIPv6
		} else {
			ipInfo = primaryIPv6
		}
	}
	return ipInfo
}

// generateServerName generates a random server name
func generateServerName() (string, error) {
	randomHex, err := generateRandomHex(8) // 8 hex chars = 4 bytes
	if err != nil {
		return "", fmt.Errorf("failed to generate random hex: %w", err)
	}
	return fmt.Sprintf("voyager-%s.cloudserver.nz", randomHex), nil
}

// promptUserConfirmation asks the user for confirmation and returns true if they confirm
func promptUserConfirmation() bool {
	log.WithField("component", "main").Info("")
	log.WithField("component", "main").Print("do you want to proceed? (yes/no): ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		log.WithField("component", "main").Fatalf("failed to read input: %v", err)
	}

	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes"
}

// displayServerConfiguration prints the server configuration details to the console
func displayServerConfiguration(
	targetProject *voyager.Project,
	targetLocation *voyager.Location,
	targetPlan *voyager.Plan,
	targetOS *voyager.ShortOsImageVersion,
	serverName string,
	tailscaleEnabled bool,
) {
	log.WithField("component", "main").Info("")
	log.WithField("component", "main").Info("server configuration:")
	log.WithField("component", "main").Infof("  - project: %s", targetProject.Name)
	log.WithField("component", "main").Infof("  - location: %s", targetLocation.Name)
	log.WithField("component", "main").Infof("  - plan: %s", targetPlan.Name)
	log.WithField("component", "main").Infof("  - hostname: %s", serverName)
	log.WithField("component", "main").Infof("  - os: %s", targetOS.Name)
	log.WithField("component", "main").Infof("  - cpu: %d cores", targetPlan.Params.CPU)
	log.WithField("component", "main").Infof("  - ram: %d MB", targetPlan.Params.Memory/(1024*1024))
	log.WithField("component", "main").Infof("  - disk: %d GB", targetPlan.Params.Disk)
	log.WithField("component", "main").Infof("  - tailscale: %v", tailscaleEnabled)

	pricePerHour := float64(targetPlan.TokensPerHour) * 0.0025
	pricePerMonth := float64(targetPlan.TokensPerMonth) * 0.0025
	log.WithField("component", "main").Infof("  - price: $%.4f/hr ($%.2f/month)", pricePerHour, pricePerMonth)
}

// validateServerConfiguration validates and returns the server configuration components
func validateServerConfiguration(voyagerClient *voyager.Client, targetProject *voyager.Project, config *Config) (*voyager.Location, *voyager.Plan, *voyager.ShortOsImageVersion) {
	// Validate location
	locations, err := voyagerClient.GetLocations()
	if err != nil {
		log.WithField("component", "main").Fatalf("failed to get locations: %v", err)
	}

	var targetLocation *voyager.Location
	for _, location := range locations {
		if location.ID == config.Voyager.Server.Location {
			targetLocation = &location
			break
		}
	}

	if targetLocation == nil {
		log.Fatalf("location id %d not found", config.Voyager.Server.Location)
	}

	// Validate plan and check if available for location
	plans, err := voyagerClient.GetProjectPlans(targetProject.ID)
	if err != nil {
		log.WithField("component", "main").Fatalf("failed to get plans: %v", err)
	}

	var targetPlan *voyager.Plan
	for _, plan := range plans {
		if plan.ID == config.Voyager.Server.Plan {
			targetPlan = &plan
			break
		}
	}

	if targetPlan == nil {
		log.WithField("component", "main").Fatalf("plan id %d not found", config.Voyager.Server.Plan)
	}

	// Check if plan is available for the location
	planAvailableForLocation := false
	for _, location := range targetPlan.AvailableLocations {
		if location.ID == config.Voyager.Server.Location {
			planAvailableForLocation = true
			break
		}
	}

	if !planAvailableForLocation {
		log.Fatalf("plan '%s' (id: %d) is not available for location '%s' (id: %d)",
			targetPlan.Name, targetPlan.ID, targetLocation.Name, targetLocation.ID)
	}

	// Validate OS
	var targetOS *voyager.ShortOsImageVersion
	for _, osImage := range targetPlan.AvailableOSImageVersions {
		if osImage.ID == config.Voyager.Server.OperatingSystem {
			targetOS = &osImage
			break
		}
	}

	if targetOS == nil {
		log.Fatalf("operating system id %d not found or not available for plan '%s'",
			config.Voyager.Server.OperatingSystem, targetPlan.Name)
	}

	return targetLocation, targetPlan, targetOS
}

// getSSHKeyID retrieves an SSH key ID from the Voyager account.
// If preferredID is provided and exists in the account, it is used.
// Otherwise, falls back to the first available SSH key.
// TODO: In the future, allow user to select from multiple SSH keys
func getSSHKeyID(voyagerClient *voyager.Client, preferredID int) (int, error) {
	sshKeys, err := voyagerClient.GetSSHKeys()
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve SSH keys: %w", err)
	}

	if len(sshKeys) == 0 {
		return 0, fmt.Errorf("no SSH keys found in account - please add an SSH key at https://cloudserver.nz/account#sshkeys")
	}

	// Check if preferred ID exists in the account
	if preferredID > 0 {
		for _, key := range sshKeys {
			if key.ID == preferredID {
				log.WithField("component", "voyager").Infof("using preferred SSH key: %s (id: %d)", key.Name, key.ID)
				return key.ID, nil
			}
		}
		log.WithField("component", "voyager").Warnf("preferred SSH key (id: %d) not found in account, using first available", preferredID)
	}

	// TODO: Allow user selection when multiple SSH keys are available
	if len(sshKeys) > 1 {
		log.WithField("component", "voyager").Warnf("multiple SSH keys found (%d), using first: %s (id: %d)", len(sshKeys), sshKeys[0].Name, sshKeys[0].ID)
	} else {
		log.WithField("component", "voyager").Infof("using ssh key: %s (id: %d)", sshKeys[0].Name, sshKeys[0].ID)
	}

	return sshKeys[0].ID, nil
}

// initializeTailscale creates and authenticates a Tailscale client if enabled.
// Returns nil if Tailscale is disabled, otherwise returns authenticated client or error.
func initializeTailscale(config *Config) (*tailscale.Client, error) {
	if !config.Tailscale.Enabled {
		log.WithField("component", "tailscale").Info("tailscale integration disabled")
		return nil, nil
	}

	// Validate required credentials
	if config.Tailscale.API.ClientID == "" ||
		config.Tailscale.API.ClientSecret == "" ||
		config.Tailscale.API.Tailnet == "" {
		return nil, fmt.Errorf("tailscale is enabled but required API credentials are missing")
	}

	tsClient := tailscale.NewClient(
		config.Tailscale.API.BaseURL,
		config.Tailscale.API.ClientID,
		config.Tailscale.API.ClientSecret,
		config.Tailscale.API.Tailnet,
	)

	if err := tsClient.GetAccessToken(); err != nil {
		return nil, fmt.Errorf("failed to authenticate with Tailscale: %w", err)
	}

	if err := tsClient.ValidateToken(); err != nil {
		return nil, fmt.Errorf("failed to validate Tailscale token: %w", err)
	}

	log.WithField("component", "tailscale").Info("tailscale client initialized successfully")
	return tsClient, nil
}

// generateTailscaleCommands creates a Tailscale auth key and returns installation commands.
// Returns empty slice if tsClient is nil (Tailscale disabled).
func generateTailscaleCommands(tsClient *tailscale.Client, config *Config) ([]string, error) {
	if tsClient == nil {
		return []string{}, nil
	}

	keyResp, err := tsClient.CreateKey(config.Tailscale.Tags)
	if err != nil {
		return nil, fmt.Errorf("failed to create Tailscale auth key: %w", err)
	}

	installCmd := fmt.Sprintf(
		"curl -fsSL https://tailscale.com/install.sh | sh && tailscale up --authkey=%s",
		keyResp.Key,
	)

	if config.Tailscale.ExitNode {
		installCmd += " --advertise-exit-node"
	}

	log.WithField("component", "tailscale").Infof("auth key created: %s", keyResp.ID)
	return []string{installCmd}, nil
}

// buildCloudInitUserData constructs the cloud-init userData from configuration and commands
func buildCloudInitUserData(config *Config, tailscaleCommands []string) string {
	userData := "#cloud-config\nruncmd:\n"

	// Add custom runcmd from config
	if config.Voyager.Server.RunCmd != "" {
		for _, line := range strings.Split(config.Voyager.Server.RunCmd, "\n") {
			if strings.TrimSpace(line) != "" {
				userData += fmt.Sprintf("  - %s\n", line)
			}
		}
	}

	// Add Tailscale commands
	for _, cmd := range tailscaleCommands {
		userData += fmt.Sprintf("  - %s\n", cmd)
	}

	// Add fail2ban if enabled
	if config.Voyager.Server.Fail2Ban {
		userData += "  - apt update && apt install fail2ban -y\n"
	}

	return userData
}

// createAndMonitorServer creates a server and polls for its status
func createAndMonitorServer(voyagerClient *voyager.Client, targetProject *voyager.Project, config *Config, serverName, userData string, sshKeyID int) *voyager.Server {
	// Create the server
	createReq := voyager.CreateServerRequest{
		Name:                      serverName,
		LocationID:                config.Voyager.Server.Location,
		PlanID:                    config.Voyager.Server.Plan,
		SSHKeys:                   []int{sshKeyID},
		IPTypes:                   []string{"IPv4", "IPv6"},
		IsDisasterRecoveryEnabled: false,
		OSImageVersionID:          config.Voyager.Server.OperatingSystem,
		UserData:                  userData,
		FQDNs:                     []string{serverName},
	}

	server, err := voyagerClient.CreateServer(targetProject.ID, createReq)
	if err != nil {
		log.WithField("component", "main").Fatalf("failed to create server: %v", err)
	}

	// Poll for server to be fully started
	log.WithField("component", "main").Info("checking creation status")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeout := time.After(60 * time.Second)

	for {
		select {
		case <-timeout:
			log.WithField("component", "main").Warn("timeout waiting for server to start. the server might still be starting.")
			log.WithField("component", "main").Infof("current status: %s", server.Status)
			return server
		case <-ticker.C:
			server, err = voyagerClient.GetServer(server.ID)
			if err != nil {
				log.WithField("component", "main").Warnf("error checking server status: %v", err)
				continue
			}

			if server == nil {
				log.WithField("component", "main").Warn("server not found during polling")
				continue
			}

			if server.Status == "started" {
				log.WithField("component", "main").Infof("server %d started successfully", server.ID)

				ipInfo := formatServerIPs(*server)
				if ipInfo != "" {
					log.WithField("component", "main").Infof("- id: %d (%s) | host: %s (%s)", server.ID, server.Status, server.Name, ipInfo)
				} else {
					log.WithField("component", "main").Infof("- id: %d (%s) | host: %s", server.ID, server.Status, server.Name)
				}
				return server
			}
		}
	}
}

func runListServers(config *Config) {
	voyagerClient := initVoyagerClient(config)
	targetProject := getOrCreateProject(voyagerClient, config, true)

	servers, err := voyagerClient.ListServers(targetProject.ID, config.Voyager.Project.Name)
	if err != nil {
		log.WithField("component", "main").Fatalf("failed to list servers: %v", err)
	}

	if len(servers) == 0 {
		log.WithField("component", "main").Info("No servers found.")
	} else {
		log.WithField("component", "main").Info("")
		log.WithField("component", "main").Info("servers:")
		for _, server := range servers {
			ipInfo := formatServerIPs(server)
			if ipInfo != "" {
				log.WithField("component", "main").Infof("- id: %d (%s) | host: %s (%s)", server.ID, server.Status, server.Name, ipInfo)
			} else {
				log.WithField("component", "main").Infof("- id: %d (%s) | host: %s", server.ID, server.Status, server.Name)
			}
		}
	}
	log.WithField("component", "main").Info("")
}

func runCreateServer(config *Config, forceCreate bool) {
	// Step 1: Initialize Tailscale (if enabled)
	tsClient, err := initializeTailscale(config)
	if err != nil {
		log.WithField("component", "main").Fatalf("Tailscale initialization failed: %v", err)
	}

	// Step 2: Initialize Voyager
	voyagerClient := initVoyagerClient(config)
	targetProject := getOrCreateProject(voyagerClient, config, true)

	// Step 3: Validate server configuration
	targetLocation, targetPlan, targetOS := validateServerConfiguration(voyagerClient, targetProject, config)

	// Step 4: Retrieve SSH key ID (use config preference if valid, otherwise first available)
	preferredSSHKey := 0
	if len(config.Voyager.Server.SSHKeys) > 0 {
		preferredSSHKey = config.Voyager.Server.SSHKeys[0]
	}
	sshKeyID, err := getSSHKeyID(voyagerClient, preferredSSHKey)
	if err != nil {
		log.WithField("component", "main").Fatalf("Failed to retrieve SSH key: %v", err)
	}

	// Step 5: Generate server name
	serverName, err := generateServerName()
	if err != nil {
		log.WithField("component", "main").Fatalf("Failed to generate server name: %v", err)
	}

	// Step 6: Display configuration and get user confirmation
	displayServerConfiguration(targetProject, targetLocation, targetPlan, targetOS, serverName, config.Tailscale.Enabled)
	if forceCreate {
		log.WithField("component", "main").Warn("force mode enabled: skipping confirmation prompt")
	} else {
		if !promptUserConfirmation() {
			log.WithField("component", "main").Info("server creation cancelled")
			return
		}
	}

	// Step 7: Generate Tailscale commands (if enabled)
	tailscaleCommands, err := generateTailscaleCommands(tsClient, config)
	if err != nil {
		log.WithField("component", "main").Fatalf("Failed to generate Tailscale commands: %v", err)
	}

	// Step 8: Build cloud-init userData
	userData := buildCloudInitUserData(config, tailscaleCommands)

	// Step 9: Create and monitor server
	createAndMonitorServer(voyagerClient, targetProject, config, serverName, userData, sshKeyID)
}

func runDeleteServer(config *Config, requestedServerID int) {
	voyagerClient := initVoyagerClient(config)
	targetProject := getOrCreateProject(voyagerClient, config, false)

	if targetProject == nil {
		log.WithField("component", "main").Fatalf("Project '%s' not found", config.Voyager.Project.Name)
	}

	// List servers
	servers, err := voyagerClient.ListServers(targetProject.ID, config.Voyager.Project.Name)
	if err != nil {
		log.WithField("component", "main").Fatalf("failed to list servers: %v", err)
	}

	log.WithField("component", "main").Info("")

	if len(servers) == 0 {
		log.WithField("component", "main").Info("no servers found.")
		return
	}

	log.WithField("component", "main").Info("servers available for deletion:")

	for _, server := range servers {
		ipInfo := formatServerIPs(server)
		if ipInfo != "" {
			log.WithField("component", "main").Infof("- id: %d (%s) | host: %s (%s)", server.ID, server.Status, server.Name, ipInfo)
		} else {
			log.WithField("component", "main").Infof("- id: %d (%s) | host: %s", server.ID, server.Status, server.Name)
		}
	}
	log.WithField("component", "main").Info("")

	serverIDs := make(map[int]bool, len(servers))
	for _, server := range servers {
		serverIDs[server.ID] = true
	}

	if requestedServerID < 0 {
		log.WithField("component", "main").Fatal("server ID must be a positive integer")
	}

	var serverID int
	if requestedServerID > 0 {
		serverID = requestedServerID
		log.WithField("component", "main").Infof("using provided server ID: %d", serverID)
	} else {
		// Ask user for server ID
		reader := bufio.NewReader(os.Stdin)
		log.WithField("component", "main").Print("enter the id of the server to delete: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("failed to read input: %v", err)
		}

		input = strings.TrimSpace(input)
		serverID, err = strconv.Atoi(input)
		if err != nil {
			log.Fatalf("invalid server ID: %v", err)
		}
	}

	if serverID <= 0 {
		log.WithField("component", "main").Fatal("server ID must be a positive integer")
	}

	if !serverIDs[serverID] {
		log.WithField("component", "main").Fatalf("server id %d not found in project '%s'. run -list and retry", serverID, config.Voyager.Project.Name)
	}

	// Delete the server
	if err := voyagerClient.DeleteServer(serverID); err != nil {
		log.WithField("component", "main").Fatalf("failed to delete server: %v", err)
	}

	// Poll for deletion
	log.WithField("component", "main").Info("polling for server deletion...")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeout := time.After(20 * time.Second) // 10 attempts * 2 seconds

	for {
		select {
		case <-timeout:
			log.WithField("component", "main").Warn("Timeout waiting for server deletion confirmation. The server might still be deleting.")
			return
		case <-ticker.C:
			server, err := voyagerClient.GetServer(serverID)
			if err != nil {
				log.WithField("component", "main").Warnf("Error checking server status: %v", err)
				continue
			}

			if server == nil {
				log.WithField("component", "main").Infof("server %d deleted successfully", serverID)
				return
			}

			log.WithField("component", "main").Infof("server %d status: %s", serverID, server.Status)
		}
	}
}
