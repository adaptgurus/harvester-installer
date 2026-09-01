package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConnectedSettingsValidate(t *testing.T) {
	settings := platformSettings{
		ConnectivityMode: "CONNECTED",
		Timezone:         "Asia/Kolkata",
		NTPServers:       []string{"ntp.layersentry.internal"},
		DNSServers:       []string{"10.10.10.53"},
	}
	if issues := validatePlatformSettings(settings); len(issues) != 0 {
		t.Fatalf("valid settings rejected: %#v", issues)
	}
}

func TestAirgapRequiresRegistryMirrors(t *testing.T) {
	settings := platformSettings{
		ConnectivityMode: "AIRGAP",
		Timezone:         "UTC",
		NTPServers:       []string{"10.10.10.123"},
		DNSServers:       []string{"10.10.10.53"},
	}
	issues := validatePlatformSettings(settings)
	if len(issues) == 0 {
		t.Fatal("AIRGAP settings without a registry mirror were accepted")
	}
	found := false
	for _, item := range issues {
		if item.Field == "registryMirrors" && item.Code == "required_for_airgap" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected required_for_airgap issue, got %#v", issues)
	}
}

func TestAirgapSettingsValidate(t *testing.T) {
	settings := platformSettings{
		ConnectivityMode: "AIRGAP",
		Timezone:         "UTC",
		NTPServers:       []string{"10.10.10.123"},
		DNSServers:       []string{"10.10.10.53"},
		RegistryMirrors: map[string][]string{
			"docker.io": {"https://registry.layersentry.internal"},
		},
	}
	if issues := validatePlatformSettings(settings); len(issues) != 0 {
		t.Fatalf("valid AIRGAP settings rejected: %#v", issues)
	}
}

func TestValidationEndpointRejectsUnknownFields(t *testing.T) {
	handler := newHandler(log.New(&bytes.Buffer{}, "", 0))
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/validate/platform-settings",
		strings.NewReader(`{"connectivityMode":"CONNECTED","timezone":"UTC","ntpServers":["ntp.internal"],"dnsServers":["10.0.0.53"],"unexpected":true}`),
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: got %d, want %d", response.Code, http.StatusBadRequest)
	}
	var payload errorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "invalid_json" {
		t.Fatalf("unexpected error code: %q", payload.Error)
	}
}

func TestValidationEndpointReturnsUnprocessableEntity(t *testing.T) {
	handler := newHandler(log.New(&bytes.Buffer{}, "", 0))
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/validate/platform-settings",
		strings.NewReader(`{"connectivityMode":"AIRGAP","timezone":"UTC","ntpServers":["10.0.0.123"],"dnsServers":["10.0.0.53"]}`),
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unexpected status: got %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
	var payload validationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Valid || len(payload.Issues) == 0 {
		t.Fatalf("invalid request reported as valid: %#v", payload)
	}
}

func TestCapabilitiesExplicitlyDisableMutationAndShell(t *testing.T) {
	capabilities := currentCapabilities()
	if !capabilities.ReadOnly {
		t.Fatal("controller scaffold must remain read-only")
	}
	if capabilities.MutatingOperations {
		t.Fatal("controller scaffold unexpectedly advertises mutating operations")
	}
	if capabilities.ShellExecution {
		t.Fatal("controller scaffold unexpectedly advertises shell execution")
	}
	if capabilities.LifecycleState != "BUNDLED_NOT_INSTALLED" {
		t.Fatalf("unexpected lifecycle state: %q", capabilities.LifecycleState)
	}
}

func TestBuildIdentity(t *testing.T) {
	oldVersion, oldCommit, oldEpoch := version, sourceCommit, buildEpoch
	t.Cleanup(func() {
		version, sourceCommit, buildEpoch = oldVersion, oldCommit, oldEpoch
	})
	version = "v1.0.0"
	sourceCommit = strings.Repeat("a", 40)
	buildEpoch = "1788307200"
	if err := validateBuildIdentity(); err != nil {
		t.Fatalf("valid immutable build identity rejected: %v", err)
	}
	version = "latest"
	if err := validateBuildIdentity(); err == nil {
		t.Fatal("floating controller version was accepted")
	}
}
