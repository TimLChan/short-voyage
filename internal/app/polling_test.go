package app

import (
	"testing"
	"time"

	"short-voyage/voyager"
)

func TestCreateAndMonitorServerPolling(t *testing.T) {
	project := &voyager.Project{ID: 10, Name: "main"}
	cfg := workflowConfig()

	t.Run("eventually reaches started status", func(t *testing.T) {
		withFastPolling(t, time.Millisecond, 40*time.Millisecond, 40*time.Millisecond)

		getServerCalls := 0
		fake := &fakeVoyagerClient{
			createServerFn: func(projectID int, req voyager.CreateServerRequest) (*voyager.Server, error) {
				return &voyager.Server{ID: 77, Name: req.Name, Status: "creating"}, nil
			},
			getServerFn: func(serverID int) (*voyager.Server, error) {
				getServerCalls++
				if getServerCalls == 1 {
					return &voyager.Server{ID: serverID, Name: "srv", Status: "provisioning"}, nil
				}
				return &voyager.Server{ID: serverID, Name: "srv", Status: "started"}, nil
			},
		}

		server, err := createAndMonitorServer(fake, project, cfg, "srv", "#cloud-config\nruncmd:\n", 99)
		if err != nil {
			t.Fatalf("createAndMonitorServer() unexpected error: %v", err)
		}
		if server == nil {
			t.Fatal("createAndMonitorServer() returned nil server")
		}
		if server.Status != "started" {
			t.Fatalf("createAndMonitorServer() final status = %q, want %q", server.Status, "started")
		}
		if getServerCalls < 2 {
			t.Fatalf("createAndMonitorServer() poll calls = %d, want at least 2", getServerCalls)
		}
	})

	t.Run("continues when server is temporarily nil", func(t *testing.T) {
		withFastPolling(t, time.Millisecond, 40*time.Millisecond, 40*time.Millisecond)

		getServerCalls := 0
		fake := &fakeVoyagerClient{
			createServerFn: func(projectID int, req voyager.CreateServerRequest) (*voyager.Server, error) {
				return &voyager.Server{ID: 88, Name: req.Name, Status: "creating"}, nil
			},
			getServerFn: func(serverID int) (*voyager.Server, error) {
				getServerCalls++
				if getServerCalls == 1 {
					return nil, nil
				}
				return &voyager.Server{ID: serverID, Name: "srv", Status: "started"}, nil
			},
		}

		server, err := createAndMonitorServer(fake, project, cfg, "srv", "#cloud-config\nruncmd:\n", 99)
		if err != nil {
			t.Fatalf("createAndMonitorServer() unexpected error: %v", err)
		}
		if server == nil || server.Status != "started" {
			t.Fatalf("createAndMonitorServer() returned %+v, want started server", server)
		}
		if getServerCalls < 2 {
			t.Fatalf("createAndMonitorServer() poll calls = %d, want at least 2", getServerCalls)
		}
	})

	t.Run("returns last known server state on timeout", func(t *testing.T) {
		withFastPolling(t, time.Millisecond, 12*time.Millisecond, 40*time.Millisecond)

		getServerCalls := 0
		fake := &fakeVoyagerClient{
			createServerFn: func(projectID int, req voyager.CreateServerRequest) (*voyager.Server, error) {
				return &voyager.Server{ID: 99, Name: req.Name, Status: "queued"}, nil
			},
			getServerFn: func(serverID int) (*voyager.Server, error) {
				getServerCalls++
				return &voyager.Server{ID: serverID, Name: "srv", Status: "provisioning"}, nil
			},
		}

		server, err := createAndMonitorServer(fake, project, cfg, "srv", "#cloud-config\nruncmd:\n", 99)
		if err != nil {
			t.Fatalf("createAndMonitorServer() unexpected error: %v", err)
		}
		if server == nil {
			t.Fatal("createAndMonitorServer() returned nil server")
		}
		if server.Status == "started" {
			t.Fatalf("createAndMonitorServer() status = %q, want non-started status", server.Status)
		}
		if getServerCalls == 0 {
			t.Fatal("createAndMonitorServer() did not poll server status")
		}
	})
}

func TestRunDeletePolling(t *testing.T) {
	cfg := workflowConfig()
	project := voyager.Project{ID: 10, Name: cfg.Voyager.Project.Name}

	t.Run("succeeds when server disappears during polling", func(t *testing.T) {
		withFastPolling(t, time.Millisecond, 40*time.Millisecond, 40*time.Millisecond)

		pollCalls := 0
		fake := &fakeVoyagerClient{
			getProjectsFn: func() ([]voyager.Project, error) {
				return []voyager.Project{project}, nil
			},
			listServersFn: func(projectID int, projectName string, silent ...bool) ([]voyager.Server, error) {
				if len(silent) > 0 && silent[0] {
					pollCalls++
					if pollCalls == 1 {
						return []voyager.Server{{ID: 42, Name: "srv", Status: "deleting"}}, nil
					}
					return nil, nil
				}
				return []voyager.Server{{ID: 42, Name: "srv", Status: "started"}}, nil
			},
			deleteServerFn: func(serverID int) error {
				return nil
			},
		}

		withFakeVoyagerClient(t, fake)

		err := RunDelete(cfg, 42)
		if err != nil {
			t.Fatalf("RunDelete() unexpected error: %v", err)
		}
		if pollCalls < 2 {
			t.Fatalf("RunDelete() poll calls = %d, want at least 2", pollCalls)
		}
	})

	t.Run("returns nil when polling times out", func(t *testing.T) {
		withFastPolling(t, time.Millisecond, 40*time.Millisecond, 12*time.Millisecond)

		pollCalls := 0
		fake := &fakeVoyagerClient{
			getProjectsFn: func() ([]voyager.Project, error) {
				return []voyager.Project{project}, nil
			},
			listServersFn: func(projectID int, projectName string, silent ...bool) ([]voyager.Server, error) {
				if len(silent) > 0 && silent[0] {
					pollCalls++
					return []voyager.Server{{ID: 42, Name: "srv", Status: "deleting"}}, nil
				}
				return []voyager.Server{{ID: 42, Name: "srv", Status: "started"}}, nil
			},
			deleteServerFn: func(serverID int) error {
				return nil
			},
		}

		withFakeVoyagerClient(t, fake)

		err := RunDelete(cfg, 42)
		if err != nil {
			t.Fatalf("RunDelete() unexpected error on timeout path: %v", err)
		}
		if pollCalls == 0 {
			t.Fatal("RunDelete() did not poll server status")
		}
	})
}
