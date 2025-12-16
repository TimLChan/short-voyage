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
	createFlag := flag.Bool("create", false, "Create Tailscale auth key and generate install command")
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

	if *createFlag {
		runCreateTailscale(config)
	} else if *deleteFlag {
		runDeleteServer(config)
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

func runCreateTailscale(config *Config) {
	tsClient := tailscale.NewClient(
		config.Tailscale.API.BaseURL,
		config.Tailscale.API.ClientID,
		config.Tailscale.API.ClientSecret,
		config.Tailscale.API.Tailnet,
	)

	// Authenticate with Tailscale
	if err := tsClient.GetAccessToken(); err != nil {
		log.Fatalf("Failed to authenticate with Tailscale: %v", err)
	}

	// Validate Tailscale token
	if err := tsClient.ValidateToken(); err != nil {
		log.Fatalf("Failed to validate Tailscale token: %v", err)
	}

	// Authenticate with Voyager
	voyagerClient := initVoyagerClient(config)

	// Get/create project
	targetProject := getOrCreateProject(voyagerClient, config, true)

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

	// Generate random server name
	randomHex, err := generateRandomHex(8) // 8 hex chars = 4 bytes
	if err != nil {
		log.WithField("component", "main").Fatalf("failed to generate random hex: %v", err)
	}
	serverName := fmt.Sprintf("voyager-%s.cloudserver.nz", randomHex)

	// Display plan information
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
	pricePerHour := float64(targetPlan.TokensPerHour) * 0.0025
	pricePerMonth := float64(targetPlan.TokensPerMonth) * 0.0025
	log.WithField("component", "main").Infof("  - price: $%.4f/hr ($%.2f/month)", pricePerHour, pricePerMonth)

	// Ask for confirmation
	log.WithField("component", "main").Info("")
	log.WithField("component", "main").Print("do you want to proceed? (yes/no): ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		log.WithField("component", "main").Fatalf("failed to read input: %v", err)
	}

	input = strings.TrimSpace(strings.ToLower(input))
	if input != "yes" {
		log.WithField("component", "main").Info("server creation cancelled")
		return
	}

	// Build user_data with runcmd + tailscale command
	userData := "#cloud-config\nruncmd:\n"
	if config.Voyager.Server.RunCmd != "" {
		// Add each line from runcmd with proper indentation
		for _, line := range strings.Split(config.Voyager.Server.RunCmd, "\n") {
			if strings.TrimSpace(line) != "" {
				userData += fmt.Sprintf("  - %s\n", line)
			}
		}
	}

	keyResp, err := tsClient.CreateKey(config.Tailscale.Tags)
	if err != nil {
		log.Fatalf("Failed to create Tailscale auth key: %v", err)
	}

	// Generate installation command
	installCmd := fmt.Sprintf("curl -fsSL https://tailscale.com/install.sh | sh && tailscale up --authkey=%s", keyResp.Key)

	if config.Tailscale.ExitNode {
		installCmd += " --advertise-exit-node"
	}
	// Add tailscale installation command
	userData += fmt.Sprintf("  - %s\n", installCmd)

	// Add fail2ban installation command
	if config.Voyager.Server.Fail2Ban {
		userData += fmt.Sprintf("  - %s\n", "apt update && apt install fail2ban -y")
	}

	// Create the server
	createReq := voyager.CreateServerRequest{
		Name:                      serverName,
		LocationID:                config.Voyager.Server.Location,
		PlanID:                    config.Voyager.Server.Plan,
		SSHKeys:                   config.Voyager.Server.SSHKeys,
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
			return
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
				return
			}
		}
	}
}

func runDeleteServer(config *Config) {
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

	// Ask user for server ID
	reader := bufio.NewReader(os.Stdin)
	log.WithField("component", "main").Print("enter the id of the server to delete: ")
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("failed to read input: %v", err)
	}

	input = strings.TrimSpace(input)
	serverID, err := strconv.Atoi(input)
	if err != nil {
		log.Fatalf("invalid server ID: %v", err)
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
