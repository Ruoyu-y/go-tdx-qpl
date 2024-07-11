// Package TDX provides functionality to interact with the Intel TDX guest device.
package tdx

// GuestDevice is the path to the TDX guest device.
const GuestDevice_1_0 = "/dev/tdx-guest"
const GuestDevice_1_5 = "/dev/tdx_guest"
const TdxVersion10 = "1.0"
const TdxVersion15 = "1.5"

// device is a handle to the TDX guest device.
type device interface {
	Fd() uintptr
}
