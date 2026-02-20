// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Adapted from confidential-sidecar-containers/pkg/common

package platform

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	PolicyFilename      = "security-policy-base64"
	HostAMDCertFilename = "host-amd-cert-base64"
	ReferenceInfoFilename = "reference-info-base64"
)

// THIMCerts represents the certificate data from the THIM endpoint,
// injected by the platform into the UVM security context.
type THIMCerts struct {
	VcekCert         string `json:"vcekCert"`
	Tcbm             string `json:"tcbm"`
	CertificateChain string `json:"certificateChain"`
	CacheControl     string `json:"cacheControl"`
}

// UvmInfo contains the platform-injected information available in C-ACI.
type UvmInfo struct {
	VcekCertChain    []byte // Concatenated VCEK cert + certificate chain
	ReferenceInfo    string // Base64-encoded UVM reference info (endorsements)
	SecurityPolicy   string // Base64-encoded security policy
}

// GetSecurityContextDir finds the security context directory in C-ACI.
// On ACI, it's injected as /security-context-* by hcsshim.
func GetSecurityContextDir() (string, error) {
	// Check env var first
	if dir := os.Getenv("UVM_SECURITY_CONTEXT_DIR"); dir != "" {
		return dir, nil
	}

	// Search root directory for security-context-* dirs
	files, err := os.ReadDir("/")
	if err != nil {
		return "", fmt.Errorf("failed to read root dir: %v", err)
	}
	for _, file := range files {
		if strings.Contains(file.Name(), "security-context-") {
			return filepath.Join("/", file.Name()), nil
		}
	}

	return "", fmt.Errorf("security context directory not found")
}

// GetUvmInfo reads the platform-injected UVM information from the security
// context directory. This includes the THIM certificates (VCEK + chain)
// and UVM reference info needed for MAA attestation.
func GetUvmInfo() (*UvmInfo, error) {
	dir, err := GetSecurityContextDir()
	if err != nil {
		// Fall back to env vars (older hcsshim versions)
		return getUvmInfoFromEnv()
	}

	info := &UvmInfo{}

	// Read THIM certs
	hostCertB64, err := os.ReadFile(filepath.Join(dir, HostAMDCertFilename))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %v", HostAMDCertFilename, err)
	}

	thim, err := parseTHIMCerts(string(hostCertB64))
	if err != nil {
		return nil, fmt.Errorf("parsing THIM certs: %v", err)
	}
	info.VcekCertChain = []byte(thim.VcekCert + thim.CertificateChain)

	// Read UVM reference info (endorsements)
	refInfo, err := os.ReadFile(filepath.Join(dir, ReferenceInfoFilename))
	if err == nil {
		info.ReferenceInfo = string(refInfo)
	}

	// Read security policy
	policy, err := os.ReadFile(filepath.Join(dir, PolicyFilename))
	if err == nil {
		info.SecurityPolicy = string(policy)
	}

	return info, nil
}

func getUvmInfoFromEnv() (*UvmInfo, error) {
	info := &UvmInfo{}

	encodedCerts := os.Getenv("UVM_HOST_AMD_CERTIFICATE")
	if encodedCerts == "" {
		return nil, fmt.Errorf("no THIM certificates available (no security context dir and UVM_HOST_AMD_CERTIFICATE not set)")
	}

	thim, err := parseTHIMCerts(encodedCerts)
	if err != nil {
		return nil, fmt.Errorf("parsing THIM certs from env: %v", err)
	}
	info.VcekCertChain = []byte(thim.VcekCert + thim.CertificateChain)
	info.ReferenceInfo = os.Getenv("UVM_REFERENCE_INFO")
	info.SecurityPolicy = os.Getenv("UVM_SECURITY_POLICY")

	return info, nil
}

func parseTHIMCerts(b64Encoded string) (*THIMCerts, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Encoded)
	if err != nil {
		// Try as raw JSON (file-based path may not be base64)
		raw = []byte(b64Encoded)
	}

	var certs THIMCerts
	if err := json.Unmarshal(raw, &certs); err != nil {
		return nil, fmt.Errorf("unmarshalling THIM certs: %v", err)
	}
	return &certs, nil
}
