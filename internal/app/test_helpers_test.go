package app

import (
	"testing"
	"time"

	appconfig "short-voyage/internal/config"
	"short-voyage/tailscale"
	"short-voyage/voyager"
)

type fakeVoyagerClient struct {
	verifyTokenFn     func() error
	getProjectsFn     func() ([]voyager.Project, error)
	createProjectFn   func(name, description string) (*voyager.Project, error)
	listServersFn     func(projectID int, projectName string, silent ...bool) ([]voyager.Server, error)
	getLocationsFn    func() ([]voyager.Location, error)
	getProjectPlansFn func(projectID int) ([]voyager.Plan, error)
	getSSHKeysFn      func() ([]voyager.SSHKey, error)
	createServerFn    func(projectID int, req voyager.CreateServerRequest) (*voyager.Server, error)
	getServerFn       func(serverID int) (*voyager.Server, error)
	deleteServerFn    func(serverID int) error
}

func (f *fakeVoyagerClient) VerifyToken() error {
	if f.verifyTokenFn != nil {
		return f.verifyTokenFn()
	}
	return nil
}

func (f *fakeVoyagerClient) GetProjects() ([]voyager.Project, error) {
	if f.getProjectsFn != nil {
		return f.getProjectsFn()
	}
	return nil, nil
}

func (f *fakeVoyagerClient) CreateProject(name, description string) (*voyager.Project, error) {
	if f.createProjectFn != nil {
		return f.createProjectFn(name, description)
	}
	return &voyager.Project{Name: name, Description: description}, nil
}

func (f *fakeVoyagerClient) ListServers(projectID int, projectName string, silent ...bool) ([]voyager.Server, error) {
	if f.listServersFn != nil {
		return f.listServersFn(projectID, projectName, silent...)
	}
	return nil, nil
}

func (f *fakeVoyagerClient) GetLocations() ([]voyager.Location, error) {
	if f.getLocationsFn != nil {
		return f.getLocationsFn()
	}
	return nil, nil
}

func (f *fakeVoyagerClient) GetProjectPlans(projectID int) ([]voyager.Plan, error) {
	if f.getProjectPlansFn != nil {
		return f.getProjectPlansFn(projectID)
	}
	return nil, nil
}

func (f *fakeVoyagerClient) GetSSHKeys() ([]voyager.SSHKey, error) {
	if f.getSSHKeysFn != nil {
		return f.getSSHKeysFn()
	}
	return nil, nil
}

func (f *fakeVoyagerClient) CreateServer(projectID int, req voyager.CreateServerRequest) (*voyager.Server, error) {
	if f.createServerFn != nil {
		return f.createServerFn(projectID, req)
	}
	return &voyager.Server{ID: 1, Name: req.Name, Status: "creating"}, nil
}

func (f *fakeVoyagerClient) GetServer(serverID int) (*voyager.Server, error) {
	if f.getServerFn != nil {
		return f.getServerFn(serverID)
	}
	return nil, nil
}

func (f *fakeVoyagerClient) DeleteServer(serverID int) error {
	if f.deleteServerFn != nil {
		return f.deleteServerFn(serverID)
	}
	return nil
}

type fakeTailscaleClient struct {
	getAccessTokenFn func() error
	validateTokenFn  func() error
	createKeyFn      func(tags []string) (*tailscale.KeyResponse, error)
}

func (f *fakeTailscaleClient) GetAccessToken() error {
	if f.getAccessTokenFn != nil {
		return f.getAccessTokenFn()
	}
	return nil
}

func (f *fakeTailscaleClient) ValidateToken() error {
	if f.validateTokenFn != nil {
		return f.validateTokenFn()
	}
	return nil
}

func (f *fakeTailscaleClient) CreateKey(tags []string) (*tailscale.KeyResponse, error) {
	if f.createKeyFn != nil {
		return f.createKeyFn(tags)
	}
	return &tailscale.KeyResponse{ID: "test-key-id", Key: "test-auth-key"}, nil
}

func withFakeVoyagerClient(t *testing.T, client voyagerClient) {
	t.Helper()
	original := newVoyagerClient
	newVoyagerClient = func(baseURL, token string) voyagerClient {
		return client
	}
	t.Cleanup(func() {
		newVoyagerClient = original
	})
}

func withFakeTailscaleClient(t *testing.T, client tailscaleClient) {
	t.Helper()
	original := newTailscaleClient
	newTailscaleClient = func(baseURL, clientID, clientSecret, tailnet string) tailscaleClient {
		return client
	}
	t.Cleanup(func() {
		newTailscaleClient = original
	})
}

func withFastPolling(t *testing.T, interval, createTimeout, deleteTimeout time.Duration) {
	t.Helper()
	originalInterval := pollInterval
	originalCreateTimeout := createPollTimeout
	originalDeleteTimeout := deletePollTimeout

	pollInterval = interval
	createPollTimeout = createTimeout
	deletePollTimeout = deleteTimeout

	t.Cleanup(func() {
		pollInterval = originalInterval
		createPollTimeout = originalCreateTimeout
		deletePollTimeout = originalDeleteTimeout
	})
}

func workflowConfig() *appconfig.Config {
	return &appconfig.Config{
		Voyager: appconfig.VoyagerConfig{
			API: appconfig.VoyagerAPIConfig{
				BaseURL: "https://voyager.test",
				Token:   "token",
			},
			Project: appconfig.ProjectConfig{
				Name:        "main",
				Description: "test project",
			},
			Server: appconfig.ServerConfig{
				Location:        1,
				Plan:            2,
				OperatingSystem: 3,
			},
		},
	}
}
