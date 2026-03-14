package app

import (
	"fmt"
	"time"

	appconfig "short-voyage/internal/config"
	"short-voyage/voyager"

	log "github.com/sirupsen/logrus"
)

const (
	tokenPricePerUnit = 0.0025
	pollInterval      = 2 * time.Second
	createPollTimeout = 60 * time.Second
	deletePollTimeout = 20 * time.Second
)

// initVoyagerClient initialises and verifies the Voyager client.
func initVoyagerClient(config *appconfig.Config) (*voyager.Client, error) {
	if config.Voyager.API.Token == "" {
		return nil, fmt.Errorf("voyager token is required in config.yaml")
	}

	client := voyager.NewClient(config.Voyager.API.BaseURL, config.Voyager.API.Token)

	if err := client.VerifyToken(); err != nil {
		return nil, fmt.Errorf("failed to verify Voyager API token: %w", err)
	}

	return client, nil
}

// getOrCreateProject retrieves the project or creates it if it does not exist.
func getOrCreateProject(client *voyager.Client, config *appconfig.Config, createIfMissing bool) (*voyager.Project, error) {
	if config.Voyager.Project.Name == "" {
		return nil, fmt.Errorf("no project specified in config.yaml")
	}

	projects, err := client.GetProjects()
	if err != nil {
		return nil, fmt.Errorf("failed to get projects: %w", err)
	}

	for i := range projects {
		if projects[i].Name == config.Voyager.Project.Name {
			return &projects[i], nil
		}
	}

	if createIfMissing {
		newProject, err := client.CreateProject(config.Voyager.Project.Name, config.Voyager.Project.Description)
		if err != nil {
			return nil, fmt.Errorf("failed to create project: %w", err)
		}
		return newProject, nil
	}

	return nil, nil
}

// formatServerIPs formats a server's primary IP addresses for display.
func formatServerIPs(server voyager.Server) string {
	var primaryIPv4 string
	for _, ipv4 := range server.IPAddresses.IPv4 {
		if ipv4.IsPrimary {
			primaryIPv4 = ipv4.IP
			break
		}
	}

	var primaryIPv6 string
	for _, ipv6 := range server.IPAddresses.IPv6 {
		if ipv6.IsPrimary {
			primaryIPv6 = ipv6.PrimaryIP
			break
		}
	}

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

func logServerSummary(server voyager.Server) {
	ipInfo := formatServerIPs(server)
	if ipInfo != "" {
		log.WithField("component", "main").Infof("- id: %d (%s) | host: %s (%s)", server.ID, server.Status, server.Name, ipInfo)
		return
	}

	log.WithField("component", "main").Infof("- id: %d (%s) | host: %s", server.ID, server.Status, server.Name)
}

func pollWithTimeout(interval, timeout time.Duration, onTick func() (bool, error)) (timedOut bool, err error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			return true, nil
		case <-ticker.C:
			done, tickErr := onTick()
			if tickErr != nil {
				return false, tickErr
			}

			if done {
				return false, nil
			}
		}
	}
}
