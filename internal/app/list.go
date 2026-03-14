package app

import (
	"fmt"

	appconfig "short-voyage/internal/config"

	log "github.com/sirupsen/logrus"
)

// RunList executes the list workflow.
func RunList(config *appconfig.Config) error {
	voyagerClient, err := initVoyagerClient(config)
	if err != nil {
		return err
	}

	targetProject, err := getOrCreateProject(voyagerClient, config, true)
	if err != nil {
		return err
	}

	servers, err := voyagerClient.ListServers(targetProject.ID, config.Voyager.Project.Name)
	if err != nil {
		return fmt.Errorf("failed to list servers: %w", err)
	}

	if len(servers) == 0 {
		log.WithField("component", "main").Info("no servers found.")
		return nil
	}

	log.WithField("component", "main").Info("")
	log.WithField("component", "main").Info("servers:")
	for _, server := range servers {
		logServerSummary(server)
	}
	log.WithField("component", "main").Info("")

	return nil
}
