// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Adapted from confidential-sidecar-containers/pkg/common

package maa

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

const (
	AttestRequestURITemplate = "https://%s/attest/SevSnpVm?api-version=2022-08-01"
)

type maaReport struct {
	SNPReport    string `json:"SnpReport"`
	CertChain    string `json:"VcekCertChain"`
	Endorsements string `json:"Endorsements,omitempty"`
}

type maaEndorsements struct {
	Uvm []string `json:"Uvm"`
}

type attestedData struct {
	Data     string `json:"data"`
	DataType string `json:"dataType"`
}

type attestSNPRequestBody struct {
	Report      string       `json:"report"`
	RuntimeData attestedData `json:"runtimeData"`
	Nonce       uint64       `json:"nonce"`
}

type maaResponse struct {
	Token string `json:"token"`
}

// GetMAAToken exchanges an SNP attestation report + VCEK cert chain for an MAA token.
// vcekCertChain is the concatenation of the VCEK cert and the certificate chain from THIM.
// uvmReferenceInfo is the optional base64-encoded UVM reference info for endorsements.
func GetMAAToken(maaEndpoint string, snpReport []byte, vcekCertChain []byte, runtimeData []byte, uvmReferenceInfo string) (string, error) {
	// Build endorsements from UVM reference info if available.
	// The reference info from the platform file is base64-encoded; MAA requires base64url.
	var encodedEndorsements string
	if uvmReferenceInfo != "" {
		// Ensure base64url encoding (replace + with -, / with _)
		cleanRef := strings.TrimSpace(uvmReferenceInfo)
		cleanRef = strings.NewReplacer("+", "-", "/", "_").Replace(cleanRef)
		endorsement := maaEndorsements{
			Uvm: []string{cleanRef},
		}
		endorsementJSON, err := json.Marshal(endorsement)
		if err != nil {
			return "", fmt.Errorf("failed to marshal endorsements: %v", err)
		}
		encodedEndorsements = base64.URLEncoding.EncodeToString(endorsementJSON)
	}

	report := maaReport{
		SNPReport:    base64.URLEncoding.EncodeToString(snpReport),
		CertChain:    base64.URLEncoding.EncodeToString(vcekCertChain),
		Endorsements: encodedEndorsements,
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("failed to marshal MAA report: %v", err)
	}

	rand.New(rand.NewSource(time.Now().UnixNano()))
	request := attestSNPRequestBody{
		Report: base64.URLEncoding.EncodeToString(reportJSON),
		RuntimeData: attestedData{
			Data:     base64.URLEncoding.EncodeToString(runtimeData),
			DataType: "JSON",
		},
		Nonce: rand.Uint64(),
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	uri := fmt.Sprintf(AttestRequestURITemplate, maaEndpoint)
	resp, err := http.Post(uri, "application/json", bytes.NewBuffer(requestJSON))
	if err != nil {
		return "", fmt.Errorf("MAA request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read MAA response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("MAA returned status %d: %s", resp.StatusCode, string(body))
	}

	var maaResp maaResponse
	if err := json.Unmarshal(body, &maaResp); err != nil {
		return "", fmt.Errorf("failed to parse MAA response: %v", err)
	}

	if maaResp.Token == "" {
		return "", fmt.Errorf("empty token in MAA response")
	}

	return maaResp.Token, nil
}
