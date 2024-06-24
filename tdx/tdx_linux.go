//go:build linux
// +build linux

package tdx

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/base64"
	"fmt"
	"unsafe"

	"github.com/Ruoyu-y/go-tdx-qpl/tdx/tdxproto"
	sdk "github.com/cc-api/cc-trusted-vmsdk/src/golang/cctrusted_vm/sdk"
	cctdx "github.com/cc-api/cc-trusted-api/common/golang/cctrusted_base/tdx"
	"github.com/vtolstov/go-ioctl"
	"golang.org/x/sys/unix"
	//"google.golang.org/protobuf/proto"
)

// tdxQuoteType is the type of quote to request.
const tdxQuoteType = uint32(2)

// IOCTL calls for quote generation
// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c#L53-L56
var (
	requestReport = uintptr(binary.BigEndian.Uint32([]byte{196, 64, 'T', 1}))
	requestQuote  = uintptr(binary.BigEndian.Uint32([]byte{128, 16, 'T', 4}))
	extendRTMR    = ioctl.IOWR('T', 0x03, 8)
)

// tdxReportUUID is a UUID to request TDX quotes.
// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.h#L70
var tdxReportUUID = []*tdxproto.UUID{{
	Value: []byte{0xe8, 0x6c, 0x04, 0x6e, 0x8c, 0xc4, 0x4d, 0x95, 0x81, 0x73, 0xfc, 0x43, 0xc1, 0xfa, 0x4f, 0x3f},
}}

// ExtendRTMR extends the RTMR with the given data.
func ExtendRTMR(tdx device, extendData []byte, index uint8) error {
	extendDataHash := sha512.Sum384(extendData)
	extendEvent := extendRTMREvent{
		algoID:       5, // HASH_ALGO_SHA384 -> linux/include/uapi/linux/hash_info.h
		digest:       &extendDataHash,
		digestLength: 48,
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, tdx.Fd(), extendRTMR, uintptr(unsafe.Pointer(&extendEvent))); errno != 0 {
		return fmt.Errorf("extending RTMR: %w", errno)
	}
	return nil
}

// ReadMeasurements reads the MRTD and RTMRs of a TDX guest.
func ReadMeasurements(tdx device) ([5][48]byte, error) {
	// TDX does not support directly reading RTMRs
	// Instead, create a new report with zeroed user data,
	// and read the RTMRs and MRTD from the report
	report, err := createReport(tdx, [64]byte{0x00})
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
	/*measurements := [5][48]byte{
		[48]byte{'1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'},
		[48]byte{'1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'},
		[48]byte{'1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'},
		[48]byte{'1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'},
		[48]byte{'1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'},
	}*/

	return measurements, nil
}

// GenerateQuote generates a TDX quote for the given user data.
// User Data may not be longer than 64 bytes.
func GenerateQuote(tdx device, userData []byte) ([]byte, error) {
	if len(userData) > 64 {
		return nil, fmt.Errorf("user data must not be longer than 64 bytes, received %d bytes", len(userData))
	}

	inst, err := sdk.GetSDKInstance(nil)
        if err != nil {
                return nil, fmt.Errorf("Failed in getting sdk instance")
        }
        report, err := inst.GetCCReport("", base64.StdEncoding.EncodeToString(userData), nil)
        if err != nil {
                return nil, err
        }

	reportContent := *report
	tdreport = cctdx.TdxReport{}
	var ok bool
	if tdreport, ok = reportContent.(cctdx.TdxReport); !ok {
		return nil, fmt.Errorf("Failed in fetching TDX Quote.")
	}
	fullReport := append(tdreport.Quote.Header.raw.Binary, tdreport.Quote.Body.raw.Binary)
	fullReport = append(fullReport, tdreport.Quote.Signature.raw.Binary)
        return fullReport, nil

	/*
	tdReport, err := createReport(tdx, reportData)
	if err != nil {
		return nil, fmt.Errorf("creating report: %w", err)
	}

	getQuoteRequest := tdxproto.Request_GetQuoteRequest{
		Report: tdReport[:],
		IdList: tdxReportUUID,
	}

	quoteType := tdxQuoteType
	quoteRequest := tdxproto.Request{
		Type: &quoteType,
		Msg:  &tdxproto.Request_GetQuoteRequest_{GetQuoteRequest: &getQuoteRequest},
	}
	serializedQuoteRequest, err := proto.Marshal(&quoteRequest)
	if err != nil {
		return nil, fmt.Errorf("marshaling quote request: %w", err)
	}

	if len(serializedQuoteRequest) > 16356 {
		return nil, fmt.Errorf("invalid serialized quote request length: expected no more than 16356 bytes, got %d bytes", len(serializedQuoteRequest))
	}
	protobufData := [16356]byte{}
	copy(protobufData[:], serializedQuoteRequest)

	var transferLength [4]byte
	binary.BigEndian.PutUint32(transferLength[:], uint32(len(serializedQuoteRequest)))

	quoteRequestWrapper := requestQuoteWrapper{
		version:     1,
		status:      0,
		inputLength: 4 + uint32(len(serializedQuoteRequest)),
		// outputLength:   uint32(unsafe.Sizeof(tdxRequestQuoteWrapper{})) - 24,
		outputLength:   16360,
		transferLength: transferLength,
		protobufData:   protobufData,
	}

	outerWrapper := requestQuoteOuterWrapper{
		blob:   uintptr(unsafe.Pointer(&quoteRequestWrapper)),
		length: unsafe.Sizeof(quoteRequestWrapper),
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, tdx.Fd(), requestQuote, uintptr(unsafe.Pointer(&outerWrapper))); errno != 0 {
		return nil, fmt.Errorf("generating quote: %w", errno)
	}

	var quoteResponse tdxproto.Response
	if err := proto.Unmarshal(quoteRequestWrapper.protobufData[:quoteRequestWrapper.outputLength-4], &quoteResponse); err != nil {
		return nil, err
	}

	return quoteResponse.GetGetQuoteResponse().Quote, nil
 */
}

func createReport(tdx device, reportData [64]byte) ([1024]byte, error) {
	var tdReport [1024]byte
	reportRequest := reportRequest{
		ReportData:       reportData,
		TdReport:         tdReport,
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(tdx.Fd()), requestReport, uintptr(unsafe.Pointer(&reportRequest))); errno != 0 {
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
type reportRequest struct {
	ReportData       [64]byte
	TdReport         [1024]byte
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
