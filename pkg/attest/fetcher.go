// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Adapted from confidential-sidecar-containers/pkg/attest

package attest

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	REPORT_REQ_SIZE  = 96
	REPORT_RSP_SIZE  = 1280
	PAYLOAD_SIZE     = 40
	PAYLOAD_SIZE_6   = 32
	MSG_REPORT_REQ   = 5
	MSG_REPORT_RSP   = 6

	SNP_GET_REPORT_IOCTL_REQ_CODE_5 = 3223868161
	SNP_GET_REPORT_IOCTL_REQ_CODE_6 = 3223343872
	REPORT_RSP_CONTAINER_SIZE_6     = 4000
)

type AttestationReportFetcher interface {
	FetchAttestationReportByte(reportData [REPORT_DATA_SIZE]byte) ([]byte, error)
}

func NewAttestationReportFetcher(allowFake bool) (AttestationReportFetcher, error) {
	switch {
	case IsSNPVM5():
		return &realAttestationReportFetcher5{}, nil
	case IsSNPVM6():
		return &realAttestationReportFetcher6{}, nil
	default:
		if allowFake {
			return &fakeAttestationReportFetcher{}, nil
		}
		return nil, fmt.Errorf("SEV device not found")
	}
}

// ============== Linux 5.x ==============

type realAttestationReportFetcher5 struct{}

func (f *realAttestationReportFetcher5) FetchAttestationReportByte(reportData [REPORT_DATA_SIZE]byte) ([]byte, error) {
	fd, err := unix.Open(SNP_DEVICE_PATH_5, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("error opening SNP device %s: %s", SNP_DEVICE_PATH_5, err)
	}
	defer unix.Close(fd)

	reportReqBytes := createReportReqBytes(reportData)
	reportRspBytes := [REPORT_RSP_SIZE]byte{}
	payload, err := createPayloadBytes5(uintptr(unsafe.Pointer(&reportReqBytes[0])), uintptr(unsafe.Pointer(&reportRspBytes[0])))
	if err != nil {
		return nil, err
	}

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(SNP_GET_REPORT_IOCTL_REQ_CODE_5),
		uintptr(unsafe.Pointer(&payload[0])),
	)

	if errno != 0 {
		return nil, fmt.Errorf("ioctl failed: %v", errno)
	}

	if status := binary.LittleEndian.Uint32(reportRspBytes[0:4]); status != 0 {
		return nil, fmt.Errorf("fetching attestation report failed, status: %v", status)
	}

	const SNP_REPORT_OFFSET = 32
	return reportRspBytes[SNP_REPORT_OFFSET : SNP_REPORT_OFFSET+ATTESTATION_REPORT_SIZE], nil
}

// ============== Linux 6.x ==============

type realAttestationReportFetcher6 struct{}

func (f *realAttestationReportFetcher6) FetchAttestationReportByte(reportData [REPORT_DATA_SIZE]byte) ([]byte, error) {
	fd, err := unix.Open(SNP_DEVICE_PATH_6, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("error opening SNP device %s: %s", SNP_DEVICE_PATH_6, err)
	}
	defer unix.Close(fd)

	reportReqBytes := createReportReqBytes(reportData)
	reportRspContainerBytes := [REPORT_RSP_CONTAINER_SIZE_6]byte{}
	payload, err := createPayloadBytes6(uintptr(unsafe.Pointer(&reportReqBytes[0])), uintptr(unsafe.Pointer(&reportRspContainerBytes[0])))
	if err != nil {
		return nil, err
	}

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(SNP_GET_REPORT_IOCTL_REQ_CODE_6),
		uintptr(unsafe.Pointer(&payload[0])),
	)

	if errno != 0 {
		return nil, fmt.Errorf("ioctl failed: %v", errno)
	}

	reportRspBytes := reportRspContainerBytes[0:REPORT_RSP_SIZE]
	if status := binary.LittleEndian.Uint32(reportRspBytes[0:4]); status != 0 {
		return nil, fmt.Errorf("fetching attestation report failed, status: %v", status)
	}

	const SNP_REPORT_OFFSET = 32
	return reportRspBytes[SNP_REPORT_OFFSET : SNP_REPORT_OFFSET+ATTESTATION_REPORT_SIZE], nil
}

// ============== Fake (for testing) ==============

type fakeAttestationReportFetcher struct{}

func (f *fakeAttestationReportFetcher) FetchAttestationReportByte(reportData [REPORT_DATA_SIZE]byte) ([]byte, error) {
	fakeReportBytes, err := hex.DecodeString("01000000010000001f00030000000000010000000000000000000000000000000200000000000000000000000000000000000000010000000000000000000031010000000000000000000000000000007ab000a323b3c873f5b81bbe584e7c1a26bcf40dc27e00f8e0d144b1ed2d14f10000000000000000000000000000000000000000000000000000000000000000b579c7d6b89f3914659abe09a004a58a1e77846b65bbdac9e29bd8f2f31b31af445a5dd40f76f71ecdd73117f1d592a38c19f1b6eee8658fbf8ff1b37f603c38929896b1cc813583bbfb21015b7aa66dd188ac79386022aec7aa4e72a7e87b0a8e0e8009183334bb0fe4f97ed89436f360b3644cd8382c7a14531a87b81a8f360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e880add9a31077e5e8f3568b4c4451f0fea4372f66e3df3c0ca3ba26f447db2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000031000000000000000000000000000000000000000000000000e6c86796cd44b0bc6b7c0d4fdab33e2807e14b5fc4538b3750921169d97bcf4447c7d3ab2a7c25f74c1641e2885c1011d025cc536f5c9a2504713136c7877f48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000247c7525e84623db9868fccf00faab22229d60aaa380213108f8875011a8f456231c5371277cc706733f4a483338fb59000000000000000000000000000000000000000000000000ed8c62254022f64630ebf97d66254dee04f708ecbe22387baf8018752fadc2b763f64bded65c94a325b6b9f22ebbb0d80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		return nil, fmt.Errorf("failed to decode fake report: %v", err)
	}
	copy(fakeReportBytes[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET+REPORT_DATA_SIZE], reportData[:])
	return fakeReportBytes, nil
}

// ============== Helper functions ==============

func createReportReqBytes(reportData [REPORT_DATA_SIZE]byte) [REPORT_REQ_SIZE]byte {
	reportReqBytes := [REPORT_REQ_SIZE]byte{}
	copy(reportReqBytes[0:REPORT_DATA_SIZE], reportData[:])
	return reportReqBytes
}

func createPayloadBytes5(reportReqPtr uintptr, reportRespPtr uintptr) ([PAYLOAD_SIZE]byte, error) {
	payload := [PAYLOAD_SIZE]byte{}
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint8(MSG_REPORT_REQ))
	binary.Write(&buf, binary.LittleEndian, uint8(MSG_REPORT_RSP))
	binary.Write(&buf, binary.LittleEndian, uint8(1))
	binary.Write(&buf, binary.LittleEndian, uint8(0))
	binary.Write(&buf, binary.LittleEndian, uint16(REPORT_REQ_SIZE))
	binary.Write(&buf, binary.LittleEndian, uint16(0))
	binary.Write(&buf, binary.LittleEndian, uint64(reportReqPtr))
	binary.Write(&buf, binary.LittleEndian, uint16(REPORT_RSP_SIZE))
	binary.Write(&buf, binary.LittleEndian, [3]uint16{})
	binary.Write(&buf, binary.LittleEndian, uint64(reportRespPtr))
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	copy(payload[:], buf.Bytes())
	return payload, nil
}

func createPayloadBytes6(reportReqPtr uintptr, reportRespPtr uintptr) ([PAYLOAD_SIZE_6]byte, error) {
	payload := [PAYLOAD_SIZE_6]byte{}
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint8(1))
	binary.Write(&buf, binary.LittleEndian, [7]uint8{})
	binary.Write(&buf, binary.LittleEndian, uint64(reportReqPtr))
	binary.Write(&buf, binary.LittleEndian, uint64(reportRespPtr))
	binary.Write(&buf, binary.LittleEndian, uint64(0))
	copy(payload[:], buf.Bytes())
	return payload, nil
}
