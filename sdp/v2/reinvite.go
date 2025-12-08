package v2

import (
	"fmt"
	"net/netip"
)

// ReInviteConfig holds configuration for building a re-INVITE SDP offer
// for content (screenshare) negotiation with BFCP floor control.
// This is designed for compatibility with Poly endpoints (Studio X, G7500)
// which require specific SDP attributes for content sharing.
type ReInviteConfig struct {
	// LocalAddr is the local IP address for the SDP origin and connection
	LocalAddr netip.Addr

	// Audio configuration (optional, set to nil to exclude audio)
	Audio *ReInviteMediaConfig

	// Video (camera) configuration - required for Poly compatibility
	// Will be set with content:main and label:1
	Video *ReInviteMediaConfig

	// Screenshare (content) configuration - required
	// Will be set with content:slides and label:3 (or BFCP.MStreamID)
	Screenshare *ReInviteMediaConfig

	// BFCP configuration (optional, set to nil to exclude BFCP)
	// Required for Poly content sharing - without BFCP, Poly will reject content
	BFCP *ReInviteBFCPConfig
}

// ReInviteMediaConfig holds configuration for a single media line in re-INVITE
type ReInviteMediaConfig struct {
	Codec     *Codec    // Selected codec
	RTPPort   uint16    // RTP port
	RTCPPort  uint16    // RTCP port (0 = RTPPort + 1)
	Direction Direction // Media direction (sendrecv, sendonly, recvonly)
	Disabled  bool      // Set to true to disable (port 0)
}

// ReInviteBFCPConfig holds BFCP configuration for re-INVITE
// Poly endpoints require BFCP for content sharing negotiation.
type ReInviteBFCPConfig struct {
	Port       uint16         // BFCP server port (our listening port)
	Proto      BfcpProto      // Protocol (TCP/BFCP or TCP/TLS/BFCP)
	Setup      BfcpSetup      // Connection setup role (passive = we are server)
	FloorCtrl  BfcpFloorCtrl  // Floor control role (s-only = we are server)
	Connection BfcpConnection // Connection reuse (new/existing)
	ConfID     uint32         // Conference ID (from initial INVITE)
	UserID     uint32         // User ID (from initial INVITE)
	FloorID    uint16         // Floor ID (from initial INVITE, typically 1)
	MStreamID  uint16         // Media stream ID - links to screenshare label (typically 3)
}

// NewReInviteConfigForPoly creates a ReInviteConfig with Poly-compatible defaults.
// This sets up the BFCP configuration for server mode (setup:passive, floorctrl:s-only).
func NewReInviteConfigForPoly(localAddr netip.Addr) *ReInviteConfig {
	return &ReInviteConfig{
		LocalAddr: localAddr,
	}
}

// WithVideo adds main video configuration to the re-INVITE.
// The video will be marked with content:main and label:1 for Poly compatibility.
func (c *ReInviteConfig) WithVideo(codec *Codec, rtpPort, rtcpPort uint16, direction Direction) *ReInviteConfig {
	c.Video = &ReInviteMediaConfig{
		Codec:     codec,
		RTPPort:   rtpPort,
		RTCPPort:  rtcpPort,
		Direction: direction,
	}
	return c
}

// WithScreenshare adds screenshare/content configuration to the re-INVITE.
// The screenshare will be marked with content:slides and label matching BFCP mstreamid.
func (c *ReInviteConfig) WithScreenshare(codec *Codec, rtpPort, rtcpPort uint16, direction Direction) *ReInviteConfig {
	c.Screenshare = &ReInviteMediaConfig{
		Codec:     codec,
		RTPPort:   rtpPort,
		RTCPPort:  rtcpPort,
		Direction: direction,
	}
	return c
}

// WithBFCP adds BFCP floor control configuration for Poly content sharing.
// For server mode (gateway sends content to Poly), use:
//   - Setup: BfcpSetupPassive (we wait for Poly to connect)
//   - FloorCtrl: BfcpFloorCtrlServer (s-only, we control the floor)
func (c *ReInviteConfig) WithBFCP(port uint16, proto BfcpProto, confID uint32, userID uint32, floorID, mstreamID uint16) *ReInviteConfig {
	c.BFCP = &ReInviteBFCPConfig{
		Port:       port,
		Proto:      proto,
		Setup:      BfcpSetupPassive,    // We are BFCP server
		FloorCtrl:  BfcpFloorCtrlServer, // s-only
		Connection: BfcpConnectionNew,
		ConfID:     confID,
		UserID:     userID,
		FloorID:    floorID,
		MStreamID:  mstreamID,
	}
	return c
}

// WithBFCPFromOffer creates BFCP config from a received BFCP offer.
// This reverses the setup and floorctrl roles appropriately.
func (c *ReInviteConfig) WithBFCPFromOffer(localPort uint16, offer *SDPBfcp, mstreamID uint16) *ReInviteConfig {
	if offer == nil {
		return c
	}
	c.BFCP = &ReInviteBFCPConfig{
		Port:       localPort,
		Proto:      offer.Proto,
		Setup:      offer.Setup.Reverse(),     // Reverse the setup role
		FloorCtrl:  offer.FloorCtrl.Reverse(), // Reverse the floor control role
		Connection: BfcpConnectionNew,
		ConfID:     offer.ConfID,
		UserID:     offer.UserID,
		FloorID:    offer.FloorID,
		MStreamID:  mstreamID,
	}
	return c
}

// WithAudio adds audio configuration to the re-INVITE.
func (c *ReInviteConfig) WithAudio(codec *Codec, rtpPort, rtcpPort uint16, direction Direction) *ReInviteConfig {
	c.Audio = &ReInviteMediaConfig{
		Codec:     codec,
		RTPPort:   rtpPort,
		RTCPPort:  rtcpPort,
		Direction: direction,
	}
	return c
}

// Build builds and marshals the re-INVITE SDP offer.
// Returns the complete SDP bytes ready to send in a SIP INVITE request.
// The m-line order for Poly compatibility is: audio, video (main), BFCP, video (slides)
func (c *ReInviteConfig) Build() ([]byte, error) {
	sdp, bfcpBytes, err := BuildReInviteOffer(c)
	if err != nil {
		return nil, err
	}
	return MarshalReInviteOffer(sdp, bfcpBytes)
}

// BuildWithSDP builds the re-INVITE and returns both the SDP structure and final bytes.
// Useful when you need to inspect or modify the SDP before sending.
func (c *ReInviteConfig) BuildWithSDP() (*SDP, []byte, error) {
	sdp, bfcpBytes, err := BuildReInviteOffer(c)
	if err != nil {
		return nil, nil, err
	}
	sdpBytes, err := MarshalReInviteOffer(sdp, bfcpBytes)
	if err != nil {
		return nil, nil, err
	}
	return sdp, sdpBytes, nil
}

// BuildReInviteOffer builds a complete SDP offer for a re-INVITE that includes
// screenshare content negotiation. This is specifically designed for Poly endpoints
// that require:
// - Main video with a=content:main and a=label:1
// - Content video with a=content:slides, a=label:3, and proper direction
// - BFCP m-line with setup:passive, floorctrl:s-only, floorid mstrm linking
//
// The returned SDP includes all m-lines in the correct order:
// audio (if present), video (main), BFCP (if present), video (slides)
//
// Note: BFCP is returned separately as bytes because it needs to be inserted
// between video and screenshare m-lines, which the standard SDP builder doesn't support.
func BuildReInviteOffer(cfg *ReInviteConfig) (*SDP, []byte, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("config is nil")
	}
	if cfg.Video == nil {
		return nil, nil, fmt.Errorf("video config is required")
	}
	if cfg.Screenshare == nil {
		return nil, nil, fmt.Errorf("screenshare config is required")
	}

	builder := (&SDP{}).Builder()
	builder.SetAddress(cfg.LocalAddr)

	if cfg.Audio != nil && cfg.Audio.Codec != nil {
		builder.SetAudio(func(b *SDPMediaBuilder) (*SDPMedia, error) {
			b.AddCodec(func(_ *CodecBuilder) (*Codec, error) {
				return cfg.Audio.Codec, nil
			}, true)
			b.SetDisabled(cfg.Audio.Disabled)
			b.SetRTPPort(cfg.Audio.RTPPort)
			b.SetRTCPPort(cfg.Audio.RTCPPort)
			b.SetDirection(cfg.Audio.Direction)
			return b.Build()
		})
	}

	builder.SetVideo(func(b *SDPMediaBuilder) (*SDPMedia, error) {
		if cfg.Video.Codec != nil {
			b.AddCodec(func(_ *CodecBuilder) (*Codec, error) {
				return cfg.Video.Codec, nil
			}, true)
		}
		b.SetDisabled(cfg.Video.Disabled)
		b.SetRTPPort(cfg.Video.RTPPort)
		b.SetRTCPPort(cfg.Video.RTCPPort)
		b.SetDirection(cfg.Video.Direction)
		b.SetContent(ContentTypeMain) // a=content:main (required for Poly)
		b.SetLabel(1)                 // a=label:1 (required for Poly)
		return b.Build()
	})

	builder.SetScreenshare(func(b *SDPMediaBuilder) (*SDPMedia, error) {
		if cfg.Screenshare.Codec != nil {
			b.AddCodec(func(_ *CodecBuilder) (*Codec, error) {
				return cfg.Screenshare.Codec, nil
			}, true)
		}
		b.SetDisabled(cfg.Screenshare.Disabled)
		b.SetRTPPort(cfg.Screenshare.RTPPort)
		b.SetRTCPPort(cfg.Screenshare.RTCPPort)
		b.SetDirection(cfg.Screenshare.Direction)
		label := uint16(3)
		if cfg.BFCP != nil && cfg.BFCP.MStreamID > 0 {
			label = cfg.BFCP.MStreamID
		}
		b.SetLabel(label) // a=label:3 (links to BFCP floorid mstrm:3)
		return b.Build()
	})

	sdpOffer, err := builder.Build()
	if err != nil {
		return nil, nil, fmt.Errorf("build SDP: %w", err)
	}

	// Build BFCP m-line separately (needs to be inserted manually due to ordering)
	var bfcpBytes []byte
	if cfg.BFCP != nil && cfg.BFCP.Port > 0 {
		bfcp := &SDPBfcp{
			Disabled:   false,
			Port:       cfg.BFCP.Port,
			Proto:      cfg.BFCP.Proto,
			Setup:      cfg.BFCP.Setup,
			Connection: cfg.BFCP.Connection,
			FloorCtrl:  cfg.BFCP.FloorCtrl,
			ConfID:     cfg.BFCP.ConfID,
			UserID:     cfg.BFCP.UserID,
			FloorID:    cfg.BFCP.FloorID,
			MStreamID:  cfg.BFCP.MStreamID,
		}
		bfcpStr, err := bfcp.Marshal()
		if err != nil {
			return nil, nil, fmt.Errorf("marshal BFCP: %w", err)
		}
		bfcpBytes = []byte(bfcpStr)
	}

	return sdpOffer, bfcpBytes, nil
}

// MarshalReInviteOffer marshals an SDP offer with BFCP inserted in the correct position.
// For Poly compatibility, the m-line order should be:
// audio, video (main), BFCP, video (slides)
//
// This function handles the insertion of BFCP bytes between the main video
// and screenshare m-lines.
func MarshalReInviteOffer(sdp *SDP, bfcpBytes []byte) ([]byte, error) {
	if sdp == nil {
		return nil, fmt.Errorf("SDP is nil")
	}

	if len(bfcpBytes) == 0 {
		return sdp.Marshal()
	}

	sdpBytes, err := sdp.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal SDP: %w", err)
	}

	// Find the screenshare m-line and insert BFCP before it
	// The screenshare m-line will have "a=content:slides"
	sdpStr := string(sdpBytes)

	// Find the second "m=video" line (screenshare)
	// First m=video is main camera, second is screenshare
	firstVideo := findMLineIndex(sdpStr, "m=video", 0)
	if firstVideo == -1 {
		// No video line, just append BFCP at the end
		return append(sdpBytes, bfcpBytes...), nil
	}

	secondVideo := findMLineIndex(sdpStr, "m=video", firstVideo+1)
	if secondVideo == -1 {
		// Only one video line (no screenshare), append BFCP at the end
		return append(sdpBytes, bfcpBytes...), nil
	}

	// Insert BFCP before the second video (screenshare) m-line
	result := make([]byte, 0, len(sdpBytes)+len(bfcpBytes))
	result = append(result, sdpBytes[:secondVideo]...)
	result = append(result, bfcpBytes...)
	result = append(result, sdpBytes[secondVideo:]...)

	return result, nil
}

// findMLineIndex finds the index of an m-line starting from the given offset
func findMLineIndex(sdp string, mline string, startOffset int) int {
	if startOffset >= len(sdp) {
		return -1
	}

	searchStr := "\r\n" + mline
	idx := indexOf(sdp[startOffset:], searchStr)
	if idx == -1 {
		// Try without \r
		searchStr = "\n" + mline
		idx = indexOf(sdp[startOffset:], searchStr)
	}
	if idx == -1 {
		return -1
	}
	return startOffset + idx + len(searchStr) - len(mline)
}

// indexOf returns the index of substr in s, or -1 if not found
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
