package main

import (
	"flag"

	"short-voyage/internal/app"
	appconfig "short-voyage/internal/config"

	nested "github.com/antonfisher/nested-logrus-formatter"
	log "github.com/sirupsen/logrus"
)

func main() {
	listFlag := flag.Bool("list", false, "List servers in the project")
	deleteFlag := flag.Bool("delete", false, "Delete a server")
	serverIDFlag := flag.Int("serverid", 0, "Server ID to delete (used with -delete)")
	createFlag := flag.Bool("create", false, "Create a server")
	forceFlag := flag.Bool("force", false, "Create server without yes/no confirmation prompt (use with -create)")
	flag.Parse()

	log.SetFormatter(&nested.Formatter{
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
		TimestampFormat: "[2006-01-02 03:04:05 PM]",
		TrimMessages:    false,
	})

	log.WithField("component", "main").Info("starting short-voyage v0.1")

	cfg, err := appconfig.Load("config.yaml")
	if err != nil {
		log.WithField("component", "main").Fatalf("Failed to load configuration: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.WithField("component", "main").Fatalf("Invalid configuration: %v", err)
	}

	if *forceFlag && !*createFlag {
		log.WithField("component", "main").Warn("-force has no effect unless -create is also provided")
	}

	if *serverIDFlag != 0 && !*deleteFlag {
		log.WithField("component", "main").Warn("-serverid has no effect unless -delete is also provided")
	}

	var runErr error
	switch {
	case *createFlag:
		runErr = app.RunCreate(cfg, *forceFlag)
	case *deleteFlag:
		runErr = app.RunDelete(cfg, *serverIDFlag)
	case *listFlag:
		runErr = app.RunList(cfg)
	default:
		runErr = app.RunList(cfg)
	}

	if runErr != nil {
		log.WithField("component", "main").Fatalf("Command failed: %v", runErr)
	}
}
