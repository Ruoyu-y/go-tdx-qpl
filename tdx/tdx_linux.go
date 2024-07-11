//go:build linux
// +build linux

package tdx

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/Ruoyu-y/go-tdx-qpl/tdx/tdxproto"
	sdk "github.com/cc-api/cc-trusted-vmsdk/src/golang/cctrusted_vm/sdk"
	cctdx "github.com/cc-api/evidence-api/common/golang/evidence_api/tdx"
	"github.com/vtolstov/go-ioctl"
	"golang.org/x/sys/unix"
)

// tdxQuoteType is the type of quote to request.
const tdxQuoteType = uint32(2)

// IOCTL calls for quote generation
// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c#L53-L56
var (
	requestReport_1_0 = ioctl.IOWR('T', 0x01, 8)
	requestQuote_1_0  = ioctl.IOR('T', 0x02, 8)
	extendRTMR_1_0    = ioctl.IOWR('T', 0x03, 8)
	requestReport_1_5 = uintptr(binary.BigEndian.Uint32([]byte{196, 64, 'T', 1}))
	requestQuote_1_5  = uintptr(binary.BigEndian.Uint32([]byte{128, 16, 'T', 4}))
)

// tdxReportUUID is a UUID to request TDX quotes.
// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.h#L70
var tdxReportUUID = []*tdxproto.UUID{{
	Value: []byte{0xe8, 0x6c, 0x04, 0x6e, 0x8c, 0xc4, 0x4d, 0x95, 0x81, 0x73, 0xfc, 0x43, 0xc1, 0xfa, 0x4f, 0x3f},
}}

// ExtendRTMR extends the RTMR with the given data.
// Note: Currently not available in upstream kernel
func ExtendRTMR_1_0(tdx device, extendData []byte, index uint8) error {
	extendDataHash := sha512.Sum384(extendData)
	extendEvent := extendRTMREvent{
		algoID:       5, // HASH_ALGO_SHA384 -> linux/include/uapi/linux/hash_info.h
		digest:       &extendDataHash,
		digestLength: 48,
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, tdx.Fd(), extendRTMR_1_0, uintptr(unsafe.Pointer(&extendEvent))); errno != 0 {
		return fmt.Errorf("extending RTMR: %w", errno)
	}
	return nil
}

// ReadMeasurements reads the MRTD and RTMRs of a TDX guest.
func ReadMeasurements(tdx device, tdxVersion string) ([5][48]byte, error) {
	// TDX does not support directly reading RTMRs
	// Instead, create a new report with zeroed user data,
	// and read the RTMRs and MRTD from the report
	report, err := createReport(tdx, [64]byte{0x00}, tdxVersion)
	if err != nil {
		return [5][48]byte{}, fmt.Errorf("creating report: %w", err)
	}

	// MRTD is located at offset 528 in the report
	// RTMRs start at offset 720 in the report
	// All measurements are 48 bytes long
	measurements := [5][48]byte{
		[48]byte(report[528:576]), // MRTD
		[48]byte(report[720:768]), // RTMR0
		[48]byte(report[768:816]), // RTMR1
		[48]byte(report[816:864]), // RTMR2
		[48]byte(report[864:912]), // RTMR3
	}

	return measurements, nil
}

func GenerateQuote(tdx device, userData []byte, nonce []byte) ([]byte, error) {
	if len(userData) > 64 {
		return nil, fmt.Errorf("user data must not be longer than 64 bytes, received %d bytes", len(userData))
	}

	inst, err := sdk.GetSDKInstance(nil)
	if err != nil {
		return nil, fmt.Errorf("Failed in getting sdk instance")
	}

	report, err := inst.GetCCReport(string(nonce), string(userData), nil)
	if err != nil {
		return nil, err
	}

	tdreport, ok := report.(*cctdx.TdxReport)
	if !ok {
		return nil, fmt.Errorf("Failed in fetching TDX Quote.")
	}

	fullReport, err := tdreport.Marshal()
	if err != nil {
		return nil, err
	}
	return fullReport, nil
}

func createReport(tdx device, reportData [64]byte, tdxVersion string) ([1024]byte, error) {
	switch tdxVersion {
	case TdxVersion10:
		return createReport10(tdx, reportData)
	case TdxVersion15:
		return createReport15(tdx, reportData)
	}
	return [1024]byte{}, fmt.Errorf("Invalid tdx version specified.")
}

func createReport10(tdx device, reportData [64]byte) ([1024]byte, error) {
	var tdReport [1024]byte
	reportRequest := reportRequest10{
		subtype:          0,
		reportData:       &reportData,
		reportDataLength: 64,
		tdReport:         &tdReport,
		tdReportLength:   1024,
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, tdx.Fd(), requestReport_1_0, uintptr(unsafe.Pointer(&reportRequest))); errno != 0 {
		return [1024]byte{}, fmt.Errorf("creating TDX report: %w", errno)
	}
	return tdReport, nil
}

func createReport15(tdx device, reportData [64]byte) ([1024]byte, error) {
	var tdReport [1024]byte
	reportRequest := reportRequest15{
		ReportData: reportData,
		TdReport:   tdReport,
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(tdx.Fd()), requestReport_1_5, uintptr(unsafe.Pointer(&reportRequest))); errno != 0 {
		return [1024]byte{}, fmt.Errorf("creating TDX report: %w", errno)
	}
	return tdReport, nil
}

// extendRTMREvent is the structure used to extend RTMRs in TDX.
// Based on the kernel patch we got to implement RTMRs for kernel 5.19.
type extendRTMREvent struct {
	algoID       uint8
	digest       *[48]byte
	digestLength uint32
}

/*
reportRequest is the structure used to create TDX reports.

Taken from pytdxmeasure:

	#
	# Reference: Structure of tdx_report_req
	#
	# struct tdx_report_req {
	#        __u8  subtype;
	#        __u64 reportdata;
	#        __u32 rpd_len;
	#        __u64 tdreport;
	#        __u32 tdr_len;
	# };
	#
*/
// Structure used in tdx 1.0
type reportRequest10 struct {
	subtype          uint8
	reportData       *[64]byte
	reportDataLength uint32
	tdReport         *[1024]byte
	tdReportLength   uint32
}

// Structure used in tdx 1.5
type reportRequest15 struct {
	ReportData [64]byte
	TdReport   [1024]byte
}

// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c#L70-L80
type requestQuoteWrapper struct {
	version        uint64
	status         uint64
	inputLength    uint32
	outputLength   uint32
	transferLength [4]byte     // BIG-ENDIAN
	protobufData   [16356]byte // https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/qgs/qgs.message.proto
}

// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c#L82-L86
type requestQuoteOuterWrapper struct {
	blob   uintptr
	length uintptr // size_t / uint64_t
}
