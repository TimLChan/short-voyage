package voyager

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetServerNotFoundReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/servers/42" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, "token")
	got, err := client.GetServer(42)
	if err != nil {
		t.Fatalf("GetServer() unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("GetServer() = %+v, want nil", got)
	}
}

func TestVerifyTokenReturnsTypedAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token")
	err := client.VerifyToken()
	if err == nil {
		t.Fatal("VerifyToken() expected error, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("VerifyToken() error type = %T, want *APIError", err)
	}

	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("APIError.StatusCode = %d, want %d", apiErr.StatusCode, http.StatusUnauthorized)
	}
	if apiErr.Method != http.MethodGet {
		t.Fatalf("APIError.Method = %q, want %q", apiErr.Method, http.MethodGet)
	}
	if apiErr.Path != "/auth" {
		t.Fatalf("APIError.Path = %q, want %q", apiErr.Path, "/auth")
	}
}

func TestListServers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/projects/10/servers" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[{"id":42,"name":"srv-1","status":"started"}]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token")

	t.Run("default logging (non-silent)", func(t *testing.T) {
		servers, err := client.ListServers(10, "my-proj")
		if err != nil {
			t.Fatalf("ListServers() unexpected error: %v", err)
		}
		if len(servers) != 1 || servers[0].ID != 42 {
			t.Fatalf("ListServers() unexpected result: %+v", servers)
		}
	})

	t.Run("silent mode", func(t *testing.T) {
		servers, err := client.ListServers(10, "my-proj", true)
		if err != nil {
			t.Fatalf("ListServers() unexpected error: %v", err)
		}
		if len(servers) != 1 || servers[0].ID != 42 {
			t.Fatalf("ListServers() unexpected result: %+v", servers)
		}
	})
}

