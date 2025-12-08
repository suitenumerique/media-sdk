// Package bfcp provides SDP parsing and answer generation for BFCP (Binary Floor Control Protocol)
// as defined in RFC 8856.
package bfcp

// Setup represents the BFCP connection setup role (RFC 4145 / RFC 8856).
type Setup string

const (
	SetupActive  Setup = "active"  // Endpoint initiates TCP connection
	SetupPassive Setup = "passive" // Endpoint accepts TCP connection
	SetupActpass Setup = "actpass" // Endpoint can do either
)

// Reverse returns the complementary setup role for SDP answer generation.
func (s Setup) Reverse() Setup {
	switch s {
	case SetupActive:
		return SetupPassive
	case SetupPassive:
		return SetupActive
	case SetupActpass:
		return SetupPassive // Server typically chooses passive
	default:
		return SetupPassive
	}
}

// Connection represents the SDP connection attribute for BFCP.
type Connection string

const (
	ConnectionNew      Connection = "new"      // New TCP connection required
	ConnectionExisting Connection = "existing" // Reuse existing connection
)

// FloorCtrl represents the floor control role in BFCP.
type FloorCtrl string

const (
	FloorCtrlClient FloorCtrl = "c-only" // Floor control client only
	FloorCtrlServer FloorCtrl = "s-only" // Floor control server only
	FloorCtrlBoth   FloorCtrl = "c-s"    // Both client and server
)

// Reverse returns the complementary floor control role for SDP answer generation.
func (f FloorCtrl) Reverse() FloorCtrl {
	switch f {
	case FloorCtrlClient:
		return FloorCtrlServer
	case FloorCtrlServer:
		return FloorCtrlClient
	case FloorCtrlBoth:
		// When remote offers c-s (both), we respond as server only (s-only)
		// This makes us the BFCP server and the remote becomes client
		return FloorCtrlServer
	default:
		return FloorCtrlServer
	}
}

// MediaInfo holds parsed BFCP media attributes from SDP.
type MediaInfo struct {
	Port       uint16     // Media port from m= line
	Proto      string     // Protocol: "TCP/BFCP" or "TCP/TLS/BFCP"
	Setup      Setup      // Connection setup role
	Connection Connection // Connection reuse policy
	FloorCtrl  FloorCtrl  // Floor control role
	ConfID     uint32     // Conference ID
	UserID     uint32     // User ID
	FloorID    uint16     // Floor ID
	MStreamID  uint16     // Media stream association (from floorid mstrm:X)
}

// AnswerConfig holds configuration for generating a BFCP SDP answer.
type AnswerConfig struct {
	Port      uint16 // Local port (0 = use offer port)
	ConfID    uint32 // Conference ID (0 = use offer value)
	UserID    uint32 // User ID (0 = use offer value)
	FloorID   uint16 // Floor ID (0 = use offer value)
	MStreamID uint16 // Media stream ID (0 = use offer value)
}
