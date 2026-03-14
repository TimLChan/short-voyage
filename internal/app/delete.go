package app

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	appconfig "short-voyage/internal/config"

	log "github.com/sirupsen/logrus"
)

// RunDelete executes the delete workflow.
func RunDelete(config *appconfig.Config, requestedServerID int) error {
	voyagerClient, err := initVoyagerClient(config)
	if err != nil {
		return err
	}

	targetProject, err := getOrCreateProject(voyagerClient, config, false)
	if err != nil {
		return err
	}

	if targetProject == nil {
		return fmt.Errorf("project '%s' not found", config.Voyager.Project.Name)
	}

	servers, err := voyagerClient.ListServers(targetProject.ID, config.Voyager.Project.Name)
	if err != nil {
		return fmt.Errorf("failed to list servers: %w", err)
	}

	log.WithField("component", "main").Info("")

	if len(servers) == 0 {
		log.WithField("component", "main").Info("no servers found.")
		return nil
	}

	log.WithField("component", "main").Info("servers available for deletion:")
	for _, server := range servers {
		logServerSummary(server)
	}
	log.WithField("component", "main").Info("")

	serverIDs := make(map[int]bool, len(servers))
	for _, server := range servers {
		serverIDs[server.ID] = true
	}

	if requestedServerID < 0 {
		return fmt.Errorf("server ID must be a positive integer")
	}

	var serverID int
	if requestedServerID > 0 {
		serverID = requestedServerID
		log.WithField("component", "main").Infof("using provided server ID: %d", serverID)
	} else {
		reader := bufio.NewReader(os.Stdin)
		log.WithField("component", "main").Print("enter the id of the server to delete: ")

		input, readErr := reader.ReadString('\n')
		if readErr != nil {
			return fmt.Errorf("failed to read input: %w", readErr)
		}

		input = strings.TrimSpace(input)
		parsedID, parseErr := strconv.Atoi(input)
		if parseErr != nil {
			return fmt.Errorf("invalid server ID: %w", parseErr)
		}

		serverID = parsedID
	}

	if serverID <= 0 {
		return fmt.Errorf("server ID must be a positive integer")
	}

	if !serverIDs[serverID] {
		return fmt.Errorf("server id %d not found in project '%s'. run -list and retry", serverID, config.Voyager.Project.Name)
	}

	if err := voyagerClient.DeleteServer(serverID); err != nil {
		return fmt.Errorf("failed to delete server: %w", err)
	}

	log.WithField("component", "main").Info("polling for server deletion...")
	timedOut, err := pollWithTimeout(pollInterval, deletePollTimeout, func() (bool, error) {
		server, pollErr := voyagerClient.GetServer(serverID)
		if pollErr != nil {
			log.WithField("component", "main").Warnf("error checking server status: %v", pollErr)
			return false, nil
		}

		if server == nil {
			log.WithField("component", "main").Infof("server %d deleted successfully", serverID)
			return true, nil
		}

		log.WithField("component", "main").Infof("server %d status: %s", serverID, server.Status)
		return false, nil
	})
	if err != nil {
		return err
	}

	if timedOut {
		log.WithField("component", "main").Warn("timeout waiting for server deletion confirmation. the server might still be deleting.")
	}

	return nil
}
