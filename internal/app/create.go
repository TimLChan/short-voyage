package app

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	appconfig "short-voyage/internal/config"
	"short-voyage/tailscale"
	"short-voyage/voyager"

	log "github.com/sirupsen/logrus"
)

func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func generateServerName() (string, error) {
	randomHex, err := generateRandomHex(8)
	if err != nil {
		return "", fmt.Errorf("failed to generate random hex: %w", err)
	}

	return fmt.Sprintf("voyager-%s.cloudserver.nz", randomHex), nil
}

func promptUserConfirmation() (bool, error) {
	log.WithField("component", "main").Info("")
	log.WithField("component", "main").Print("do you want to proceed? (yes/no): ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read input: %w", err)
	}

	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes", nil
}

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

	pricePerHour := float64(targetPlan.TokensPerHour) * tokenPricePerUnit
	pricePerMonth := float64(targetPlan.TokensPerMonth) * tokenPricePerUnit
	log.WithField("component", "main").Infof("  - price: $%.4f/hr ($%.2f/month)", pricePerHour, pricePerMonth)
}

func validateServerConfiguration(voyagerClient *voyager.Client, targetProject *voyager.Project, config *appconfig.Config) (*voyager.Location, *voyager.Plan, *voyager.ShortOsImageVersion, error) {
	locations, err := voyagerClient.GetLocations()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get locations: %w", err)
	}

	var targetLocation *voyager.Location
	for i := range locations {
		if locations[i].ID == config.Voyager.Server.Location {
			targetLocation = &locations[i]
			break
		}
	}

	if targetLocation == nil {
		return nil, nil, nil, fmt.Errorf("location id %d not found", config.Voyager.Server.Location)
	}

	plans, err := voyagerClient.GetProjectPlans(targetProject.ID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get plans: %w", err)
	}

	var targetPlan *voyager.Plan
	for i := range plans {
		if plans[i].ID == config.Voyager.Server.Plan {
			targetPlan = &plans[i]
			break
		}
	}

	if targetPlan == nil {
		return nil, nil, nil, fmt.Errorf("plan id %d not found", config.Voyager.Server.Plan)
	}

	planAvailableForLocation := false
	for _, location := range targetPlan.AvailableLocations {
		if location.ID == config.Voyager.Server.Location {
			planAvailableForLocation = true
			break
		}
	}

	if !planAvailableForLocation {
		return nil, nil, nil, fmt.Errorf(
			"plan '%s' (id: %d) is not available for location '%s' (id: %d)",
			targetPlan.Name,
			targetPlan.ID,
			targetLocation.Name,
			targetLocation.ID,
		)
	}

	var targetOS *voyager.ShortOsImageVersion
	for i := range targetPlan.AvailableOSImageVersions {
		if targetPlan.AvailableOSImageVersions[i].ID == config.Voyager.Server.OperatingSystem {
			targetOS = &targetPlan.AvailableOSImageVersions[i]
			break
		}
	}

	if targetOS == nil {
		return nil, nil, nil, fmt.Errorf(
			"operating system id %d not found or not available for plan '%s'",
			config.Voyager.Server.OperatingSystem,
			targetPlan.Name,
		)
	}

	return targetLocation, targetPlan, targetOS, nil
}

func getSSHKeyID(voyagerClient *voyager.Client, preferredID int) (int, error) {
	sshKeys, err := voyagerClient.GetSSHKeys()
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve SSH keys: %w", err)
	}

	if len(sshKeys) == 0 {
		return 0, fmt.Errorf("no SSH keys found in account - please add an SSH key at https://cloudserver.nz/account#sshkeys")
	}

	if preferredID > 0 {
		for _, key := range sshKeys {
			if key.ID == preferredID {
				log.WithField("component", "voyager").Infof("using preferred SSH key: %s (id: %d)", key.Name, key.ID)
				return key.ID, nil
			}
		}
		log.WithField("component", "voyager").Warnf("preferred SSH key (id: %d) not found in account, using first available", preferredID)
	}

	if len(sshKeys) > 1 {
		log.WithField("component", "voyager").Warnf("multiple SSH keys found (%d), using first: %s (id: %d)", len(sshKeys), sshKeys[0].Name, sshKeys[0].ID)
	} else {
		log.WithField("component", "voyager").Infof("using ssh key: %s (id: %d)", sshKeys[0].Name, sshKeys[0].ID)
	}

	return sshKeys[0].ID, nil
}

func initializeTailscale(config *appconfig.Config) (*tailscale.Client, error) {
	if !config.Tailscale.Enabled {
		log.WithField("component", "tailscale").Info("tailscale integration disabled")
		return nil, nil
	}

	if config.Tailscale.API.ClientID == "" || config.Tailscale.API.ClientSecret == "" || config.Tailscale.API.Tailnet == "" {
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

func generateTailscaleCommands(tsClient *tailscale.Client, config *appconfig.Config) ([]string, error) {
	if tsClient == nil {
		return []string{}, nil
	}

	keyResp, err := tsClient.CreateKey(config.Tailscale.Tags)
	if err != nil {
		return nil, fmt.Errorf("failed to create Tailscale auth key: %w", err)
	}

	installCmd := fmt.Sprintf("curl -fsSL https://tailscale.com/install.sh | sh && tailscale up --authkey=%s", keyResp.Key)
	if config.Tailscale.ExitNode {
		installCmd += " --advertise-exit-node"
	}

	log.WithField("component", "tailscale").Infof("auth key created: %s", keyResp.ID)
	return []string{installCmd}, nil
}

func buildCloudInitUserData(config *appconfig.Config, tailscaleCommands []string) string {
	var builder strings.Builder
	builder.WriteString("#cloud-config\nruncmd:\n")

	if config.Voyager.Server.RunCmd != "" {
		for _, line := range strings.Split(config.Voyager.Server.RunCmd, "\n") {
			if strings.TrimSpace(line) != "" {
				builder.WriteString("  - ")
				builder.WriteString(line)
				builder.WriteByte('\n')
			}
		}
	}

	for _, cmd := range tailscaleCommands {
		builder.WriteString("  - ")
		builder.WriteString(cmd)
		builder.WriteByte('\n')
	}

	if config.Voyager.Server.Fail2Ban {
		builder.WriteString("  - apt update && apt install fail2ban -y\n")
		builder.WriteString("  - echo 'sshd_backend = systemd' >> /etc/fail2ban/paths-debian.conf\n")
		builder.WriteString("  - echo -e '[sshd]\\nenabled = true\\nbantime = 10h\\nfindtime = 10h\\nmaxretry = 3\\nbantime.increment = true\\nbantime.factor = 2' >> /etc/fail2ban/jail.d/sshd-custom.conf\n")
		builder.WriteString("  - systemctl restart fail2ban\n")
	}

	return builder.String()
}

func createAndMonitorServer(voyagerClient *voyager.Client, targetProject *voyager.Project, config *appconfig.Config, serverName, userData string, sshKeyID int) (*voyager.Server, error) {
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
		return nil, fmt.Errorf("failed to create server: %w", err)
	}

	serverID := server.ID

	log.WithField("component", "main").Info("checking creation status")
	timedOut, err := pollWithTimeout(pollInterval, createPollTimeout, func() (bool, error) {
		currentServer, err := voyagerClient.GetServer(serverID)
		if err != nil {
			log.WithField("component", "main").Warnf("error checking server status: %v", err)
			return false, nil
		}

		if currentServer == nil {
			log.WithField("component", "main").Warn("server not found during polling")
			return false, nil
		}

		server = currentServer

		if server.Status == "started" {
			log.WithField("component", "main").Infof("server %d started successfully", serverID)
			logServerSummary(*server)
			return true, nil
		}

		return false, nil
	})
	if err != nil {
		return nil, err
	}

	if timedOut {
		log.WithField("component", "main").Warn("timeout waiting for server to start. the server might still be starting.")
		if server != nil {
			log.WithField("component", "main").Infof("current status: %s", server.Status)
		}
	}

	return server, nil
}

// RunCreate executes the create workflow.
func RunCreate(config *appconfig.Config, forceCreate bool) error {
	tsClient, err := initializeTailscale(config)
	if err != nil {
		return fmt.Errorf("tailscale initialization failed: %w", err)
	}

	voyagerClient, err := initVoyagerClient(config)
	if err != nil {
		return err
	}

	targetProject, err := getOrCreateProject(voyagerClient, config, true)
	if err != nil {
		return err
	}

	targetLocation, targetPlan, targetOS, err := validateServerConfiguration(voyagerClient, targetProject, config)
	if err != nil {
		return err
	}

	preferredSSHKey := 0
	if len(config.Voyager.Server.SSHKeys) > 0 {
		preferredSSHKey = config.Voyager.Server.SSHKeys[0]
	}

	sshKeyID, err := getSSHKeyID(voyagerClient, preferredSSHKey)
	if err != nil {
		return fmt.Errorf("failed to retrieve SSH key: %w", err)
	}

	serverName, err := generateServerName()
	if err != nil {
		return fmt.Errorf("failed to generate server name: %w", err)
	}

	displayServerConfiguration(targetProject, targetLocation, targetPlan, targetOS, serverName, config.Tailscale.Enabled)
	if forceCreate {
		log.WithField("component", "main").Warn("force mode enabled: skipping confirmation prompt")
	} else {
		confirmed, err := promptUserConfirmation()
		if err != nil {
			return err
		}

		if !confirmed {
			log.WithField("component", "main").Info("server creation cancelled")
			return nil
		}
	}

	tailscaleCommands, err := generateTailscaleCommands(tsClient, config)
	if err != nil {
		return fmt.Errorf("failed to generate tailscale commands: %w", err)
	}

	userData := buildCloudInitUserData(config, tailscaleCommands)
	_, err = createAndMonitorServer(voyagerClient, targetProject, config, serverName, userData, sshKeyID)
	return err
}
