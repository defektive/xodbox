package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestAPIHealthEndpoint(t *testing.T) {
	h := APIHAndler("/api", "")

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), `"status":"ok"`) {
		t.Errorf("body = %q, want to contain {\"status\":\"ok\"}", rr.Body.String())
	}
}

func TestAuthRequiredMissingHeader(t *testing.T) {
	h := APIHAndler("/api", "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/private/bots", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rr.Body.String(), "unauthorized") {
		t.Errorf("body = %q, want to contain 'unauthorized'", rr.Body.String())
	}
}

func TestAuthRequiredBadToken(t *testing.T) {
	h := APIHAndler("/api", "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/private/bots", nil)
	req.Header.Set("Authorization", "Token wrong")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestAuthRequiredEmptyConfiguredToken(t *testing.T) {
	// Empty token must reject all callers, even those sending matching empty token.
	h := APIHAndler("/api", "")

	req := httptest.NewRequest(http.MethodGet, "/api/private/bots", nil)
	req.Header.Set("Authorization", "Token ")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("empty configured token should always reject; status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestAuthRequiredValidToken(t *testing.T) {
	h := APIHAndler("/api", "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/private/bots", nil)
	req.Header.Set("Authorization", "Token secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	// Auth passes; downstream handler runs and returns 200 with JSON array body.
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (body=%q)", rr.Code, http.StatusOK, rr.Body.String())
	}
}
