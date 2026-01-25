// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Adapted from confidential-sidecar-containers/pkg/attest

package attest

import (
	"crypto/sha256"
	"os"
)

const (
	ATTESTATION_REPORT_SIZE = 1184
	REPORT_DATA_SIZE        = 64
	REPORT_DATA_OFFSET      = 80
	HOST_DATA_SIZE          = 32
	HOST_DATA_OFFSET        = 192
)

const SNP_DEVICE_PATH_5 = "/dev/sev"
const SNP_DEVICE_PATH_6 = "/dev/sev-guest"

// IsSNPVM5 checks if running in SNP VM with Linux kernel 5.x
func IsSNPVM5() bool {
	_, err := os.Stat(SNP_DEVICE_PATH_5)
	return err == nil
}

// IsSNPVM6 checks if running in SNP VM with Linux kernel 6.x
func IsSNPVM6() bool {
	_, err := os.Stat(SNP_DEVICE_PATH_6)
	return err == nil
}

// IsSNPVM checks if running in any SNP VM
func IsSNPVM() bool {
	return IsSNPVM5() || IsSNPVM6()
}

// GenerateReportData creates the 64-byte report data from input bytes
// MAA expects SHA256 hash of the runtime data in the first 32 bytes
func GenerateReportData(inputBytes []byte) [REPORT_DATA_SIZE]byte {
	reportData := [REPORT_DATA_SIZE]byte{}
	if inputBytes != nil {
		hash := sha256.Sum256(inputBytes)
		copy(reportData[:32], hash[:])
	}
	return reportData
}
