// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Adapted for scittish from confidential-sidecar-containers

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/scittish/attest-helper/pkg/attest"
	"github.com/scittish/attest-helper/pkg/maa"
	"github.com/scittish/attest-helper/pkg/platform"
)

type AttestResponse struct {
	Token  string `json:"token,omitempty"`
	Report string `json:"report,omitempty"`
	Error  string `json:"error,omitempty"`
}

func main() {
	runtimeDataB64 := flag.String("runtime-data", "", "Base64-encoded runtime data (hash will be used as report data)")
	maaEndpoint := flag.String("maa-endpoint", "sharedeus.eus.attest.azure.net", "MAA endpoint")
	rawOnly := flag.Bool("raw", false, "Return raw attestation report only (no MAA token)")
	allowFake := flag.Bool("allow-fake", false, "Allow fake attestation report on non-SNP systems")

	flag.Parse()

	response := AttestResponse{}

	// Decode runtime data
	var runtimeData []byte
	var err error
	if *runtimeDataB64 != "" {
		runtimeData, err = base64.StdEncoding.DecodeString(*runtimeDataB64)
		if err != nil {
			response.Error = fmt.Sprintf("failed to decode runtime data: %v", err)
			outputJSON(response)
			os.Exit(1)
		}
	}

	// Check if we're on an SNP VM
	if !attest.IsSNPVM() && !*allowFake {
		response.Error = "not running on SNP VM and --allow-fake not set"
		outputJSON(response)
		os.Exit(1)
	}

	// Get attestation report
	reportFetcher, err := attest.NewAttestationReportFetcher(*allowFake)
	if err != nil {
		response.Error = fmt.Sprintf("failed to create report fetcher: %v", err)
		outputJSON(response)
		os.Exit(1)
	}

	reportData := attest.GenerateReportData(runtimeData)
	reportBytes, err := reportFetcher.FetchAttestationReportByte(reportData)
	if err != nil {
		response.Error = fmt.Sprintf("failed to fetch attestation report: %v", err)
		outputJSON(response)
		os.Exit(1)
	}

	if *rawOnly {
		response.Report = base64.StdEncoding.EncodeToString(reportBytes)
		outputJSON(response)
		return
	}

	// Read platform-injected VCEK cert chain and UVM reference info.
	// On C-ACI, THIM certs are in /security-context-*/host-amd-cert-base64.
	// These are required by MAA to validate the SNP report signature.
	var vcekCertChain []byte
	var uvmReferenceInfo string

	uvmInfo, err := platform.GetUvmInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read platform UVM info: %v\n", err)
		// Continue with empty cert chain — MAA will reject if it can't validate
	} else {
		vcekCertChain = uvmInfo.VcekCertChain
		uvmReferenceInfo = uvmInfo.ReferenceInfo
	}

	// Get MAA token
	token, err := maa.GetMAAToken(*maaEndpoint, reportBytes, vcekCertChain, runtimeData, uvmReferenceInfo)
	if err != nil {
		response.Error = fmt.Sprintf("failed to get MAA token: %v", err)
		outputJSON(response)
		os.Exit(1)
	}

	response.Token = token
	outputJSON(response)
}

func outputJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.Encode(v)
}
