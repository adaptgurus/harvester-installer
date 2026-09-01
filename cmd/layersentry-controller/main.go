package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"
)

const (
	productName             = "LayerSentry"
	productVersion          = "v1.0"
	embeddedPlatformName    = "Harvester"
	embeddedPlatformVersion = "v1.8.2"
	componentName           = "layersentry-controller"
	controllerMode          = "bootstrap-validation"
	maxRequestBytes         = 1 << 20
)

var (
	version      = "dev"
	sourceCommit = "uncommitted"
	buildEpoch   = "0"
	commitRE     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hostnameRE   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

type buildInformation struct {
	Component               string `json:"component"`
	Version                 string `json:"version"`
	SourceCommit            string `json:"sourceCommit"`
	BuildEpoch              string `json:"buildEpoch"`
	Product                 string `json:"product"`
	ProductVersion          string `json:"productVersion"`
	EmbeddedPlatform        string `json:"embeddedPlatform"`
	EmbeddedPlatformVersion string `json:"embeddedPlatformVersion"`
	Mode                    string `json:"mode"`
	Bundled                 bool   `json:"bundled"`
	Installed               bool   `json:"installed"`
	RuntimeQualified        bool   `json:"runtimeQualified"`
	ReleaseApproved         bool   `json:"releaseApproved"`
}

type capabilityInformation struct {
	Mode                    string   `json:"mode"`
	ReadOnly                bool     `json:"readOnly"`
	MutatingOperations      bool     `json:"mutatingOperations"`
	ShellExecution          bool     `json:"shellExecution"`
	SupportedConnectivity   []string `json:"supportedConnectivityModes"`
	ValidationCapabilities  []string `json:"validationCapabilities"`
	LifecycleState          string   `json:"lifecycleState"`
	RuntimeQualification    string   `json:"runtimeQualification"`
	InstallationDisposition string   `json:"installationDisposition"`
}

type platformSettings struct {
	ConnectivityMode string              `json:"connectivityMode"`
	Timezone         string              `json:"timezone"`
	NTPServers       []string            `json:"ntpServers"`
	DNSServers       []string            `json:"dnsServers"`
	RegistryMirrors  map[string][]string `json:"registryMirrors,omitempty"`
	ProxyURL         string              `json:"proxyUrl,omitempty"`
	NoProxy          []string            `json:"noProxy,omitempty"`
}

type validationIssue struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type validationResponse struct {
	Valid  bool              `json:"valid"`
	Issues []validationIssue `json:"issues"`
}

type statusResponse struct {
	Status    string `json:"status"`
	Component string `json:"component"`
	Mode      string `json:"mode"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type selfTestResponse struct {
	Status       string `json:"status"`
	Component    string `json:"component"`
	Version      string `json:"version"`
	SourceCommit string `json:"sourceCommit"`
	BuildEpoch   string `json:"buildEpoch"`
}

func currentBuildInformation() buildInformation {
	return buildInformation{
		Component:               componentName,
		Version:                 version,
		SourceCommit:            sourceCommit,
		BuildEpoch:              buildEpoch,
		Product:                 productName,
		ProductVersion:          productVersion,
		EmbeddedPlatform:        embeddedPlatformName,
		EmbeddedPlatformVersion: embeddedPlatformVersion,
		Mode:                    controllerMode,
		Bundled:                 true,
		Installed:               false,
		RuntimeQualified:        false,
		ReleaseApproved:         false,
	}
}

func currentCapabilities() capabilityInformation {
	return capabilityInformation{
		Mode:               controllerMode,
		ReadOnly:           true,
		MutatingOperations: false,
		ShellExecution:     false,
		SupportedConnectivity: []string{
			"CONNECTED",
			"AIRGAP",
		},
		ValidationCapabilities: []string{
			"connectivity-mode",
			"timezone",
			"ntp",
			"dns",
			"proxy",
			"registry-mirrors",
		},
		LifecycleState:          "BUNDLED_NOT_INSTALLED",
		RuntimeQualification:    "NOT_RUNTIME_QUALIFIED",
		InstallationDisposition: "INSTALL_ONLY_BY_RELEASED_BOOTSTRAP_WORKFLOW",
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(componentName, flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddress := flags.String("listen", "127.0.0.1:9443", "HTTP listen address")
	configPath := flags.String("config", "", "optional platform-settings JSON file validated before startup")
	showVersion := flags.Bool("version", false, "print immutable build information and exit")
	selfTest := flags.Bool("self-test", false, "run deterministic built-in validation tests and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}

	if *showVersion {
		if err := writeJSON(stdout, currentBuildInformation()); err != nil {
			fmt.Fprintf(stderr, "write version output: %v\n", err)
			return 1
		}
		return 0
	}
	if *selfTest {
		if err := runSelfTest(stdout); err != nil {
			fmt.Fprintf(stderr, "self-test failed: %v\n", err)
			return 1
		}
		return 0
	}

	if err := validateBuildIdentity(); err != nil {
		fmt.Fprintf(stderr, "invalid immutable build identity: %v\n", err)
		return 1
	}
	if _, _, err := net.SplitHostPort(*listenAddress); err != nil {
		fmt.Fprintf(stderr, "invalid listen address %q: %v\n", *listenAddress, err)
		return 2
	}
	if *configPath != "" {
		settings, err := loadSettingsFile(*configPath)
		if err != nil {
			fmt.Fprintf(stderr, "load startup settings: %v\n", err)
			return 1
		}
		if issues := validatePlatformSettings(settings); len(issues) != 0 {
			fmt.Fprintf(stderr, "startup settings failed validation: %s\n", formatIssues(issues))
			return 1
		}
	}

	logger := log.New(stderr, "layersentry-controller: ", log.LstdFlags|log.LUTC)
	server := &http.Server{
		Addr:              *listenAddress,
		Handler:           newHandler(logger),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          logger,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	serveResult := make(chan error, 1)
	go func() {
		logger.Printf("starting %s %s on %s in %s mode", componentName, version, server.Addr, controllerMode)
		serveResult <- server.ListenAndServe()
	}()

	select {
	case err := <-serveResult:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "HTTP server failed: %v\n", err)
			return 1
		}
		return 0
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "graceful shutdown failed: %v\n", err)
			return 1
		}
		err := <-serveResult
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "HTTP server failed during shutdown: %v\n", err)
			return 1
		}
		return 0
	}
}

func newHandler(logger *log.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", requireMethod(http.MethodGet, func(w http.ResponseWriter, _ *http.Request) {
		writeHTTPJSON(w, http.StatusOK, statusResponse{Status: "ok", Component: componentName, Mode: controllerMode})
	}))
	mux.HandleFunc("/readyz", requireMethod(http.MethodGet, func(w http.ResponseWriter, _ *http.Request) {
		writeHTTPJSON(w, http.StatusOK, statusResponse{Status: "ready", Component: componentName, Mode: controllerMode})
	}))
	mux.HandleFunc("/v1/version", requireMethod(http.MethodGet, func(w http.ResponseWriter, _ *http.Request) {
		writeHTTPJSON(w, http.StatusOK, currentBuildInformation())
	}))
	mux.HandleFunc("/v1/capabilities", requireMethod(http.MethodGet, func(w http.ResponseWriter, _ *http.Request) {
		writeHTTPJSON(w, http.StatusOK, currentCapabilities())
	}))
	mux.HandleFunc("/v1/validate/platform-settings", requireMethod(http.MethodPost, validateSettingsHandler))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeHTTPJSON(w, http.StatusNotFound, errorResponse{Error: "not_found", Message: "endpoint does not exist"})
	})
	return requestLoggingMiddleware(logger, mux)
}

func requireMethod(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeHTTPJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method_not_allowed", Message: "method is not allowed for this endpoint"})
			return
		}
		next(w, r)
	}
}

func validateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var settings platformSettings
	if err := decoder.Decode(&settings); err != nil {
		writeHTTPJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_json", Message: cleanDecodeError(err)})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeHTTPJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_json", Message: "request body must contain exactly one JSON object"})
		return
	}
	issues := validatePlatformSettings(settings)
	status := http.StatusOK
	if len(issues) != 0 {
		status = http.StatusUnprocessableEntity
	}
	writeHTTPJSON(w, status, validationResponse{Valid: len(issues) == 0, Issues: issues})
}

func requestLoggingMiddleware(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		logger.Printf("method=%s path=%q remote=%q duration_ms=%d", r.Method, r.URL.Path, r.RemoteAddr, time.Since(started).Milliseconds())
	})
}

func validatePlatformSettings(settings platformSettings) []validationIssue {
	issues := make([]validationIssue, 0)
	mode := strings.ToUpper(strings.TrimSpace(settings.ConnectivityMode))
	if mode == "" {
		issues = append(issues, issue("connectivityMode", "required", "connectivity mode is required"))
	} else if mode != "CONNECTED" && mode != "AIRGAP" {
		issues = append(issues, issue("connectivityMode", "unsupported", "connectivity mode must be CONNECTED or AIRGAP"))
	}

	timezone := strings.TrimSpace(settings.Timezone)
	if timezone == "" {
		issues = append(issues, issue("timezone", "required", "timezone is required"))
	} else if _, err := time.LoadLocation(timezone); err != nil {
		issues = append(issues, issue("timezone", "invalid", "timezone must be a valid IANA timezone"))
	}

	issues = append(issues, validateEndpointList("ntpServers", settings.NTPServers, false)...)
	issues = append(issues, validateEndpointList("dnsServers", settings.DNSServers, true)...)
	issues = append(issues, validateNoProxy(settings.NoProxy)...)
	issues = append(issues, validateProxy(settings.ProxyURL)...)
	issues = append(issues, validateRegistryMirrors(mode, settings.RegistryMirrors)...)
	return issues
}

func validateEndpointList(field string, values []string, requireIP bool) []validationIssue {
	issues := make([]validationIssue, 0)
	if len(values) == 0 {
		return append(issues, issue(field, "required", field+" must contain at least one endpoint"))
	}
	seen := map[string]struct{}{}
	for index, raw := range values {
		value := strings.TrimSpace(raw)
		path := fmt.Sprintf("%s[%d]", field, index)
		if value == "" {
			issues = append(issues, issue(path, "required", "endpoint must not be empty"))
			continue
		}
		if strings.ContainsAny(value, "\t\r\n /") {
			issues = append(issues, issue(path, "invalid", "endpoint contains prohibited whitespace or path characters"))
			continue
		}
		if requireIP {
			if net.ParseIP(value) == nil {
				issues = append(issues, issue(path, "invalid", "DNS endpoint must be an IPv4 or IPv6 address"))
				continue
			}
		} else if net.ParseIP(value) == nil && !validHostname(value) {
			issues = append(issues, issue(path, "invalid", "endpoint must be an IP address or DNS hostname"))
			continue
		}
		canonical := strings.ToLower(value)
		if _, exists := seen[canonical]; exists {
			issues = append(issues, issue(path, "duplicate", "endpoint is duplicated"))
			continue
		}
		seen[canonical] = struct{}{}
	}
	return issues
}

func validateRegistryMirrors(mode string, mirrors map[string][]string) []validationIssue {
	issues := make([]validationIssue, 0)
	if mode == "AIRGAP" && len(mirrors) == 0 {
		return append(issues, issue("registryMirrors", "required_for_airgap", "AIRGAP mode requires explicit registry mirrors"))
	}
	for source, endpoints := range mirrors {
		trimmedSource := strings.TrimSpace(source)
		field := fmt.Sprintf("registryMirrors[%q]", source)
		if trimmedSource == "" || !validHostname(trimmedSource) {
			issues = append(issues, issue(field, "invalid_source_registry", "source registry must be a DNS hostname"))
		}
		if len(endpoints) == 0 {
			issues = append(issues, issue(field, "required", "registry mirror must contain at least one endpoint"))
			continue
		}
		seen := map[string]struct{}{}
		for index, raw := range endpoints {
			path := fmt.Sprintf("%s[%d]", field, index)
			parsed, err := url.Parse(strings.TrimSpace(raw))
			if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
				issues = append(issues, issue(path, "invalid", "mirror endpoint must be an http or https URL without credentials, query, or fragment"))
				continue
			}
			if parsed.Path != "" && parsed.Path != "/" {
				issues = append(issues, issue(path, "invalid", "mirror endpoint must not contain a path"))
				continue
			}
			canonical := strings.ToLower(strings.TrimSuffix(parsed.String(), "/"))
			if _, exists := seen[canonical]; exists {
				issues = append(issues, issue(path, "duplicate", "mirror endpoint is duplicated"))
				continue
			}
			seen[canonical] = struct{}{}
		}
	}
	return issues
}

func validateProxy(raw string) []validationIssue {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Fragment != "" {
		return []validationIssue{issue("proxyUrl", "invalid", "proxy URL must be http or https and must not contain embedded credentials or a fragment")}
	}
	return nil
}

func validateNoProxy(values []string) []validationIssue {
	issues := make([]validationIssue, 0)
	seen := map[string]struct{}{}
	for index, raw := range values {
		value := strings.TrimSpace(raw)
		path := fmt.Sprintf("noProxy[%d]", index)
		if value == "" || strings.ContainsAny(value, "\t\r\n ") {
			issues = append(issues, issue(path, "invalid", "noProxy value must be non-empty and contain no whitespace"))
			continue
		}
		canonical := strings.ToLower(value)
		if _, exists := seen[canonical]; exists {
			issues = append(issues, issue(path, "duplicate", "noProxy value is duplicated"))
			continue
		}
		seen[canonical] = struct{}{}
	}
	return issues
}

func validHostname(value string) bool {
	if len(value) > 253 || !hostnameRE.MatchString(value) || strings.Contains(value, "..") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func validateBuildIdentity() error {
	if version != "v1.0.0" {
		return fmt.Errorf("controller version must be v1.0.0, got %q", version)
	}
	if !commitRE.MatchString(sourceCommit) {
		return fmt.Errorf("source commit must be exactly 40 lowercase hex characters")
	}
	epoch, err := strconv.ParseInt(buildEpoch, 10, 64)
	if err != nil || epoch <= 0 {
		return fmt.Errorf("build epoch must be a positive Unix timestamp")
	}
	return nil
}

func runSelfTest(stdout io.Writer) error {
	if err := validateBuildIdentity(); err != nil {
		return err
	}
	connected := platformSettings{
		ConnectivityMode: "CONNECTED",
		Timezone:         "Asia/Kolkata",
		NTPServers:       []string{"time.example.internal"},
		DNSServers:       []string{"10.0.0.53"},
	}
	if issues := validatePlatformSettings(connected); len(issues) != 0 {
		return fmt.Errorf("valid CONNECTED settings rejected: %s", formatIssues(issues))
	}
	airgap := platformSettings{
		ConnectivityMode: "AIRGAP",
		Timezone:         "UTC",
		NTPServers:       []string{"10.0.0.123"},
		DNSServers:       []string{"10.0.0.53"},
		RegistryMirrors: map[string][]string{
			"docker.io": {"https://registry.layersentry.internal"},
		},
	}
	if issues := validatePlatformSettings(airgap); len(issues) != 0 {
		return fmt.Errorf("valid AIRGAP settings rejected: %s", formatIssues(issues))
	}
	airgap.RegistryMirrors = nil
	if issues := validatePlatformSettings(airgap); len(issues) == 0 {
		return errors.New("AIRGAP settings without registry mirrors were accepted")
	}
	return writeJSON(stdout, selfTestResponse{
		Status:       "pass",
		Component:    componentName,
		Version:      version,
		SourceCommit: sourceCommit,
		BuildEpoch:   buildEpoch,
	})
}

func loadSettingsFile(path string) (platformSettings, error) {
	file, err := os.Open(path)
	if err != nil {
		return platformSettings{}, err
	}
	defer file.Close()
	limited := io.LimitReader(file, maxRequestBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return platformSettings{}, err
	}
	if len(data) > maxRequestBytes {
		return platformSettings{}, fmt.Errorf("settings file exceeds %d bytes", maxRequestBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var settings platformSettings
	if err := decoder.Decode(&settings); err != nil {
		return platformSettings{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return platformSettings{}, errors.New("settings file must contain exactly one JSON object")
	}
	return settings, nil
}

func issue(field, code, message string) validationIssue {
	return validationIssue{Field: field, Code: code, Message: message}
}

func formatIssues(issues []validationIssue) string {
	parts := make([]string, 0, len(issues))
	for _, item := range issues {
		parts = append(parts, item.Field+":"+item.Code)
	}
	return strings.Join(parts, ",")
}

func cleanDecodeError(err error) string {
	message := err.Error()
	if strings.Contains(message, "http: request body too large") {
		return fmt.Sprintf("request body exceeds %d bytes", maxRequestBytes)
	}
	return message
}

func writeHTTPJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(value)
}
