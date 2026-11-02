package app

import (
	"errors"
	"strings"
	"testing"
	"time"

	"short-voyage/voyager"
)

func TestRunList(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		cfg := workflowConfig()

		project := voyager.Project{ID: 10, Name: cfg.Voyager.Project.Name}
		listCalled := false

		fake := &fakeVoyagerClient{
			getProjectsFn: func() ([]voyager.Project, error) {
				return []voyager.Project{project}, nil
			},
			listServersFn: func(projectID int, projectName string, silent ...bool) ([]voyager.Server, error) {
				listCalled = true
				if projectID != project.ID {
					t.Fatalf("ListServers projectID = %d, want %d", projectID, project.ID)
				}
				if projectName != cfg.Voyager.Project.Name {
					t.Fatalf("ListServers projectName = %q, want %q", projectName, cfg.Voyager.Project.Name)
				}
				return []voyager.Server{{ID: 42, Name: "srv", Status: "started"}}, nil
			},
		}

		withFakeVoyagerClient(t, fake)

		if err := RunList(cfg); err != nil {
			t.Fatalf("RunList() unexpected error: %v", err)
		}

		if !listCalled {
			t.Fatal("RunList() did not call ListServers")
		}
	})

	t.Run("returns wrapped list error", func(t *testing.T) {
		cfg := workflowConfig()
		listErr := errors.New("list failed")

		fake := &fakeVoyagerClient{
			getProjectsFn: func() ([]voyager.Project, error) {
				return []voyager.Project{{ID: 10, Name: cfg.Voyager.Project.Name}}, nil
			},
			listServersFn: func(projectID int, projectName string, silent ...bool) ([]voyager.Server, error) {
				return nil, listErr
			},
		}

		withFakeVoyagerClient(t, fake)

		err := RunList(cfg)
		if err == nil {
			t.Fatal("RunList() expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to list servers") {
			t.Fatalf("RunList() error = %q, want wrapped list error", err.Error())
		}
	})
}

func TestRunCreate(t *testing.T) {
	t.Run("happy path with force create", func(t *testing.T) {
		cfg := workflowConfig()
		withFastPolling(t, time.Millisecond, 40*time.Millisecond, 40*time.Millisecond)

		project := voyager.Project{ID: 10, Name: cfg.Voyager.Project.Name}
		location := voyager.Location{ID: cfg.Voyager.Server.Location, Name: "auckland"}
		plan := voyager.Plan{
			ID:                 cfg.Voyager.Server.Plan,
			Name:               "xxs",
			TokensPerHour:      100,
			TokensPerMonth:     1000,
			Params:             voyager.PlanData{CPU: 1, Memory: 2 * 1024 * 1024 * 1024, Disk: 25},
			AvailableLocations: []voyager.Location{{ID: cfg.Voyager.Server.Location, Name: "auckland"}},
			AvailableOSImageVersions: []voyager.ShortOsImageVersion{{
				ID:   cfg.Voyager.Server.OperatingSystem,
				Name: "debian 12",
			}},
		}

		createCalled := false
		getServerCalls := 0

		fake := &fakeVoyagerClient{
			getProjectsFn: func() ([]voyager.Project, error) {
				return []voyager.Project{project}, nil
			},
			getLocationsFn: func() ([]voyager.Location, error) {
				return []voyager.Location{location}, nil
			},
			getProjectPlansFn: func(projectID int) ([]voyager.Plan, error) {
				return []voyager.Plan{plan}, nil
			},
			getSSHKeysFn: func() ([]voyager.SSHKey, error) {
				return []voyager.SSHKey{{ID: 99, Name: "default"}}, nil
			},
			createServerFn: func(projectID int, req voyager.CreateServerRequest) (*voyager.Server, error) {
				createCalled = true
				if projectID != project.ID {
					t.Fatalf("CreateServer projectID = %d, want %d", projectID, project.ID)
				}
				if req.OSImageVersionID != cfg.Voyager.Server.OperatingSystem {
					t.Fatalf("CreateServer OSImageVersionID = %d, want %d", req.OSImageVersionID, cfg.Voyager.Server.OperatingSystem)
				}
				return &voyager.Server{ID: 77, Name: req.Name, Status: "creating"}, nil
			},
			getServerFn: func(serverID int) (*voyager.Server, error) {
				getServerCalls++
				return &voyager.Server{ID: serverID, Name: "srv", Status: "started"}, nil
			},
		}

		withFakeVoyagerClient(t, fake)

		err := RunCreate(cfg, true)
		if err != nil {
			t.Fatalf("RunCreate() unexpected error: %v", err)
		}
		if !createCalled {
			t.Fatal("RunCreate() did not call CreateServer")
		}
		if getServerCalls == 0 {
			t.Fatal("RunCreate() did not poll server status")
		}
	})

	t.Run("returns wrapped SSH key retrieval error", func(t *testing.T) {
		cfg := workflowConfig()

		project := voyager.Project{ID: 10, Name: cfg.Voyager.Project.Name}
		location := voyager.Location{ID: cfg.Voyager.Server.Location, Name: "auckland"}
		plan := voyager.Plan{
			ID:                 cfg.Voyager.Server.Plan,
			Name:               "xxs",
			AvailableLocations: []voyager.Location{{ID: cfg.Voyager.Server.Location}},
			AvailableOSImageVersions: []voyager.ShortOsImageVersion{{
				ID: cfg.Voyager.Server.OperatingSystem,
			}},
		}

		fake := &fakeVoyagerClient{
			getProjectsFn: func() ([]voyager.Project, error) {
				return []voyager.Project{project}, nil
			},
			getLocationsFn: func() ([]voyager.Location, error) {
				return []voyager.Location{location}, nil
			},
			getProjectPlansFn: func(projectID int) ([]voyager.Plan, error) {
				return []voyager.Plan{plan}, nil
			},
			getSSHKeysFn: func() ([]voyager.SSHKey, error) {
				return []voyager.SSHKey{}, nil
			},
		}

		withFakeVoyagerClient(t, fake)

		err := RunCreate(cfg, true)
		if err == nil {
			t.Fatal("RunCreate() expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to retrieve SSH key") {
			t.Fatalf("RunCreate() error = %q, want wrapped SSH key error", err.Error())
		}
	})
}

func TestRunDelete(t *testing.T) {
	t.Run("happy path with requested server ID", func(t *testing.T) {
		cfg := workflowConfig()
		withFastPolling(t, time.Millisecond, 40*time.Millisecond, 40*time.Millisecond)

		project := voyager.Project{ID: 10, Name: cfg.Voyager.Project.Name}
		deleteCalledWith := 0

		fake := &fakeVoyagerClient{
			getProjectsFn: func() ([]voyager.Project, error) {
				return []voyager.Project{project}, nil
			},
			listServersFn: func(projectID int, projectName string, silent ...bool) ([]voyager.Server, error) {
				if len(silent) > 0 && silent[0] {
					return nil, nil
				}
				return []voyager.Server{{ID: 42, Name: "srv", Status: "started"}}, nil
			},
			deleteServerFn: func(serverID int) error {
				deleteCalledWith = serverID
				return nil
			},
			getServerFn: func(serverID int) (*voyager.Server, error) {
				return nil, nil
			},
		}

		withFakeVoyagerClient(t, fake)

		err := RunDelete(cfg, 42)
		if err != nil {
			t.Fatalf("RunDelete() unexpected error: %v", err)
		}
		if deleteCalledWith != 42 {
			t.Fatalf("RunDelete() deleted server ID %d, want %d", deleteCalledWith, 42)
		}
	})

	t.Run("errors when requested server ID is not present", func(t *testing.T) {
		cfg := workflowConfig()

		project := voyager.Project{ID: 10, Name: cfg.Voyager.Project.Name}
		deleteCalled := false

		fake := &fakeVoyagerClient{
			getProjectsFn: func() ([]voyager.Project, error) {
				return []voyager.Project{project}, nil
			},
			listServersFn: func(projectID int, projectName string, silent ...bool) ([]voyager.Server, error) {
				if len(silent) > 0 && silent[0] {
					return nil, nil
				}
				return []voyager.Server{{ID: 42, Name: "srv", Status: "started"}}, nil
			},
			deleteServerFn: func(serverID int) error {
				deleteCalled = true
				return nil
			},
		}

		withFakeVoyagerClient(t, fake)

		err := RunDelete(cfg, 99)
		if err == nil {
			t.Fatal("RunDelete() expected error, got nil")
		}
		if !strings.Contains(err.Error(), "not found in project") {
			t.Fatalf("RunDelete() error = %q, want missing server error", err.Error())
		}
		if deleteCalled {
			t.Fatal("RunDelete() should not call DeleteServer for unknown server ID")
		}
	})
}
