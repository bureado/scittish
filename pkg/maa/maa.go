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
	"time"
)

const (
	AttestRequestURITemplate = "https://%s/attest/SevSnpVm?api-version=2022-08-01"
)

type maaReport struct {
	SNPReport string `json:"SnpReport"`
	CertChain string `json:"VcekCertChain,omitempty"`
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

// GetMAAToken exchanges an SNP attestation report for an MAA token
func GetMAAToken(maaEndpoint string, snpReport []byte, runtimeData []byte) (string, error) {
	// Build the MAA report structure
	report := maaReport{
		SNPReport: base64.URLEncoding.EncodeToString(snpReport),
		// Note: In a real C-ACI environment, we'd include the VCEK cert chain
		// For now, MAA will fetch it from AMD's KDS based on the chip ID in the report
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("failed to marshal MAA report: %v", err)
	}

	// Build the request body
	rand.Seed(time.Now().UnixNano())
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

	// Make HTTP request to MAA
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
