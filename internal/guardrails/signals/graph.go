package signals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrDeviceNotInGraph reports that Microsoft Graph returned no matching device.
//
// A sentinel rather than a (nil, nil) return: the lookups previously signalled
// "no error, but nothing found" by returning two nils, which callers had to know
// to disambiguate. Callers now match with errors.Is.
var ErrDeviceNotInGraph = errors.New("device not found in Microsoft Graph")

// ErrGraphStatus reports a Graph response that was neither the expected 200
// nor an error the transport surfaced. Callers distinguish it from
// ErrDeviceNotInGraph: an unexpected status is an inconclusive check, not a
// negative answer about the device.
var ErrGraphStatus = errors.New("unexpected HTTP status from Microsoft Graph")

// GraphConfig holds the Entra app-registration credentials used for the
// authoritative (tier-2) device-compliance checks. The app needs the
// application permissions Device.Read.All and DeviceManagementManagedDevices.Read.All
// (admin-consented). Secrets should come from the environment/vault, never the
// command line.
type GraphConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	// Base overrides the Graph base URL (default the beta endpoint, which carries
	// richer fields — managed-device compliance and health attestation — than
	// v1.0). TokenURL overrides the OAuth token endpoint. Both are for testing.
	Base     string
	TokenURL string
}

// Configured reports whether enough credentials are present to query Graph.
func (g GraphConfig) Configured() bool {
	return g.TenantID != "" && g.ClientID != "" && g.ClientSecret != ""
}

// GraphClient is a minimal Microsoft Graph client using the OAuth2
// client-credentials (app-only) flow. It caches the bearer token until shortly
// before expiry. It is cross-platform (net/http) and therefore CI-testable.
type GraphClient struct {
	cfg   GraphConfig
	httpc *http.Client

	mu    sync.Mutex
	token string
	exp   time.Time
}

// NewGraphClient builds a client. Base defaults to the Graph beta endpoint.
func NewGraphClient(cfg GraphConfig) *GraphClient {
	if cfg.Base == "" {
		cfg.Base = "https://graph.microsoft.com/beta"
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = "https://login.microsoftonline.com/" + cfg.TenantID + "/oauth2/v2.0/token"
	}
	return &GraphClient{cfg: cfg, httpc: &http.Client{Timeout: 20 * time.Second}}
}

// getToken returns a cached or freshly-acquired app-only bearer token.
func (c *GraphClient) getToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.exp) > time.Minute {
		return c.token, nil
	}
	form := url.Values{
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	if resp.StatusCode != http.StatusOK || tok.AccessToken == "" {
		if tok.Error != "" {
			return "", fmt.Errorf("token request failed: %s: %s", tok.Error, tok.ErrorDesc)
		}
		return "", fmt.Errorf("token request failed: HTTP %d", resp.StatusCode)
	}
	c.token = tok.AccessToken
	c.exp = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return c.token, nil
}

// get issues an authenticated GET and decodes a 200 body into out. It returns
// the HTTP status so callers can distinguish "not found" from "found".
func (c *GraphClient) get(ctx context.Context, path string, out any) (int, error) {
	tok, err := c.getToken(ctx)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Base+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode Graph response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// entraDevice is the subset of the Entra device resource we evaluate.
type entraDevice struct {
	ID             string `json:"id"`
	DeviceID       string `json:"deviceId"`
	DisplayName    string `json:"displayName"`
	IsCompliant    bool   `json:"isCompliant"`
	IsManaged      bool   `json:"isManaged"`
	AccountEnabled bool   `json:"accountEnabled"`
	TrustType      string `json:"trustType"`
}

func (c *GraphClient) entraDevice(ctx context.Context, aadDeviceID string) (*entraDevice, error) {
	path := "/devices?$filter=deviceId+eq+'" + url.QueryEscape(aadDeviceID) + "'" +
		"&$select=id,deviceId,displayName,isCompliant,isManaged,accountEnabled,trustType"
	var res struct {
		Value []entraDevice `json:"value"`
	}
	code, err := c.get(ctx, path, &res)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("%w: %d from /devices", ErrGraphStatus, code)
	}
	if len(res.Value) == 0 {
		return nil, ErrDeviceNotInGraph
	}
	return &res.Value[0], nil
}

// healthAttestation is the beta deviceHealthAttestationState subset.
type healthAttestation struct {
	SecureBoot               string `json:"secureBoot"`
	BitLockerStatus          string `json:"bitLockerStatus"`
	HealthStatusMismatchInfo string `json:"healthStatusMismatchInfo"`
	AttestationIdentityKey   string `json:"attestationIdentityKey"`
	DeviceHealthAttestation  string `json:"deviceHealthAttestationStatus"`
}

// intuneDevice is the subset of the Intune managedDevice resource we evaluate.
type intuneDevice struct {
	ID                      string             `json:"id"`
	AzureADDeviceID         string             `json:"azureADDeviceId"`
	DeviceName              string             `json:"deviceName"`
	ComplianceState         string             `json:"complianceState"`
	ManagementState         string             `json:"managementState"`
	IsEncrypted             bool               `json:"isEncrypted"`
	DeviceEnrollmentType    string             `json:"deviceEnrollmentType"`
	DeviceHealthAttestation *healthAttestation `json:"deviceHealthAttestationState"`
}

func (c *GraphClient) intuneDevice(ctx context.Context, aadDeviceID string) (*intuneDevice, error) {
	path := "/deviceManagement/managedDevices?$filter=azureADDeviceId+eq+'" + url.QueryEscape(aadDeviceID) + "'" +
		"&$select=id,azureADDeviceId,deviceName,complianceState,managementState,isEncrypted,deviceEnrollmentType,deviceHealthAttestationState"
	var res struct {
		Value []intuneDevice `json:"value"`
	}
	code, err := c.get(ctx, path, &res)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("%w: %d from /managedDevices", ErrGraphStatus, code)
	}
	if len(res.Value) == 0 {
		return nil, ErrDeviceNotInGraph
	}
	return &res.Value[0], nil
}

// aadDeviceID resolves the device's Entra (Azure AD) device ID — from the probe
// if populated, else by parsing dsregcmd.
func aadDeviceID(ctx context.Context, env *Env) (string, error) {
	if id := env.Sys.DeviceIdentity().EntraDeviceID; !isNull(id) {
		return id, nil
	}
	out, err := env.Sys.RunShell(ctx, "dsregcmd /status")
	if err != nil {
		return "", err
	}
	id := dsregParse(out)["DeviceId"]
	if isNull(id) {
		return "", fmt.Errorf("device has no Entra DeviceId (not Entra-joined)")
	}
	return id, nil
}

// RegisterGraph wires the authoritative (tier-2) Graph-backed guardrails. These
// query Entra ID and Intune for the device's real compliance and enrollment,
// which — unlike the local dsregcmd/registry signals — a local admin cannot
// spoof. The compliance/enrollment checks join the --enterprise-guardrails
// preset (Enterprise: true); attestation is opt-in.
func RegisterGraph(reg *Registry, c *GraphClient) {
	reg.Register(Guardrail{
		ID:          "graph-entra-registered",
		Description: "Device is registered and enabled in Entra ID (Graph)",
		Check:       c.checkEntraRegistered,
	})
	reg.Register(Guardrail{
		ID:          "graph-entra-compliant",
		Description: "Entra ID reports the device compliant (Graph)",
		Check:       c.checkEntraCompliant,
	})
	reg.Register(Guardrail{
		ID:          "graph-intune-enrolled",
		Description: "Device is enrolled in Intune (Graph)",
		Check:       c.checkIntuneEnrolled,
	})
	reg.Register(Guardrail{
		ID:          "graph-intune-compliant",
		Description: "Intune reports the device compliant (Graph)",
		Check:       c.checkIntuneCompliant,
	})
	reg.Register(Guardrail{
		ID:          "graph-attested",
		Description: "Intune device health attestation is healthy (Graph, TPM/DHA)",
		Check:       c.checkAttested,
	})
}

func (c *GraphClient) checkEntraRegistered(ctx context.Context, env *Env) Result {
	id, err := aadDeviceID(ctx, env)
	if err != nil {
		return errf("graph-entra-registered", err.Error())
	}
	dev, err := c.entraDevice(ctx, id)
	switch {
	case errors.Is(err, ErrDeviceNotInGraph):
		return fail("graph-entra-registered", "device "+id+" not found in Entra ID")
	case err != nil:
		return errf("graph-entra-registered", "Graph query failed: "+err.Error())
	}
	if !dev.AccountEnabled {
		return fail("graph-entra-registered", "Entra device account is disabled")
	}
	return Result{
		ID: "graph-entra-registered", Status: Pass,
		Detail: fmt.Sprintf("registered in Entra (%q, trust=%s)", dev.DisplayName, dev.TrustType),
		Data: map[string]any{
			"object_id": dev.ID, "trust_type": dev.TrustType, "is_managed": dev.IsManaged,
		},
	}
}

func (c *GraphClient) checkEntraCompliant(ctx context.Context, env *Env) Result {
	id, err := aadDeviceID(ctx, env)
	if err != nil {
		return errf("graph-entra-compliant", err.Error())
	}
	dev, err := c.entraDevice(ctx, id)
	switch {
	case errors.Is(err, ErrDeviceNotInGraph):
		return fail("graph-entra-compliant", "device "+id+" not found in Entra ID")
	case err != nil:
		return errf("graph-entra-compliant", "Graph query failed: "+err.Error())
	}
	if !dev.IsCompliant {
		return fail("graph-entra-compliant", "Entra ID reports the device as non-compliant")
	}
	return pass("graph-entra-compliant", "Entra ID reports the device compliant")
}

func (c *GraphClient) checkIntuneEnrolled(ctx context.Context, env *Env) Result {
	id, err := aadDeviceID(ctx, env)
	if err != nil {
		return errf("graph-intune-enrolled", err.Error())
	}
	dev, err := c.intuneDevice(ctx, id)
	switch {
	case errors.Is(err, ErrDeviceNotInGraph):
		return fail("graph-intune-enrolled", "device "+id+" is not enrolled in Intune")
	case err != nil:
		return errf("graph-intune-enrolled", "Graph query failed: "+err.Error())
	}
	return Result{
		ID: "graph-intune-enrolled", Status: Pass,
		Detail: fmt.Sprintf("enrolled in Intune (%q, type=%s, mgmt=%s)",
			dev.DeviceName, dev.DeviceEnrollmentType, dev.ManagementState),
		Data: map[string]any{
			"managed_device_id": dev.ID, "enrollment_type": dev.DeviceEnrollmentType,
		},
	}
}

func (c *GraphClient) checkIntuneCompliant(ctx context.Context, env *Env) Result {
	id, err := aadDeviceID(ctx, env)
	if err != nil {
		return errf("graph-intune-compliant", err.Error())
	}
	dev, err := c.intuneDevice(ctx, id)
	switch {
	case errors.Is(err, ErrDeviceNotInGraph):
		return fail("graph-intune-compliant", "device "+id+" is not enrolled in Intune")
	case err != nil:
		return errf("graph-intune-compliant", "Graph query failed: "+err.Error())
	}
	if !strings.EqualFold(dev.ComplianceState, "compliant") {
		return fail("graph-intune-compliant", "Intune compliance state is "+dev.ComplianceState)
	}
	return pass("graph-intune-compliant", "Intune reports the device compliant")
}

func (c *GraphClient) checkAttested(ctx context.Context, env *Env) Result {
	id, err := aadDeviceID(ctx, env)
	if err != nil {
		return errf("graph-attested", err.Error())
	}
	dev, err := c.intuneDevice(ctx, id)
	switch {
	case errors.Is(err, ErrDeviceNotInGraph):
		return fail("graph-attested", "device "+id+" is not enrolled in Intune")
	case err != nil:
		return errf("graph-attested", "Graph query failed: "+err.Error())
	}
	att := dev.DeviceHealthAttestation
	if att == nil || (att.SecureBoot == "" && att.BitLockerStatus == "") {
		return skip("graph-attested", "no device health attestation state reported (TPM/DHA not available)")
	}
	var problems []string
	if att.SecureBoot != "" && !strings.EqualFold(att.SecureBoot, "enabled") {
		problems = append(problems, "secure boot "+att.SecureBoot)
	}
	if att.BitLockerStatus != "" && !strings.EqualFold(att.BitLockerStatus, "enabled") &&
		!strings.EqualFold(att.BitLockerStatus, "on") {
		problems = append(problems, "BitLocker "+att.BitLockerStatus)
	}
	if !isNull(att.HealthStatusMismatchInfo) {
		problems = append(problems, "health mismatch: "+att.HealthStatusMismatchInfo)
	}
	if len(problems) > 0 {
		return fail("graph-attested", "attestation problems: "+strings.Join(problems, "; "))
	}
	return pass(
		"graph-attested",
		fmt.Sprintf("attestation healthy (secure boot=%s, BitLocker=%s)", att.SecureBoot, att.BitLockerStatus),
	)
}
