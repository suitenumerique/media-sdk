package v2

import (
	"fmt"
	"net/netip"
)

// ReInviteState captures the negotiated media state from an initial INVITE/200 OK exchange.
// This state can be used to build re-INVITE SDPs that preserve existing media (especially audio)
// while adding new media streams (like screenshare with BFCP).
//
// Usage:
//
//	// Capture state from initial negotiation
//	state := NewReInviteState(localIP)
//	state.SetAudioFromAnswer(audioCodec, localAudioPort)
//	state.SetVideoFromAnswer(videoCodec, localVideoPort, direction)
//	state.SetBFCPFromOffer(bfcpOffer, localBFCPPort)
//
//	// Later, when screenshare is needed, build re-INVITE
//	sdpBytes, err := state.BuildScreenshareReInvite(screenshareCodec, screensharePort, screenshareRTCPPort)
type ReInviteState struct {
	// LocalAddr is the local IP address for SDP origin and connection
	LocalAddr netip.Addr

	// Audio state from initial negotiation
	AudioCodec    *Codec
	AudioRTPPort  uint16
	AudioRTCPPort uint16
	AudioDir      Direction

	// Video (camera) state from initial negotiation
	VideoCodec    *Codec
	VideoRTPPort  uint16
	VideoRTCPPort uint16
	VideoDir      Direction

	// BFCP state from initial offer (if present)
	BFCPInfo     *SDPBfcp // Original BFCP from remote offer
	BFCPLocalPort uint16   // Our local BFCP server port
}

// NewReInviteState creates a new state container for re-INVITE building.
func NewReInviteState(localAddr netip.Addr) *ReInviteState {
	return &ReInviteState{
		LocalAddr: localAddr,
		AudioDir:  DirectionSendRecv, // Default for audio
		VideoDir:  DirectionSendRecv, // Default for video
	}
}

// SetAudio sets the audio state from the initial negotiation.
// The codec should be the one selected/negotiated from the initial offer.
// The ports are the local ports used in the SDP answer.
func (s *ReInviteState) SetAudio(codec *Codec, rtpPort, rtcpPort uint16, direction Direction) *ReInviteState {
	s.AudioCodec = codec
	s.AudioRTPPort = rtpPort
	s.AudioRTCPPort = rtcpPort
	s.AudioDir = direction
	return s
}

// SetAudioFromAnswer is a convenience method that sets audio with default sendrecv direction.
// RTCP port defaults to RTP port + 1.
func (s *ReInviteState) SetAudioFromAnswer(codec *Codec, rtpPort uint16) *ReInviteState {
	return s.SetAudio(codec, rtpPort, rtpPort+1, DirectionSendRecv)
}

// SetVideo sets the video (camera) state from the initial negotiation.
func (s *ReInviteState) SetVideo(codec *Codec, rtpPort, rtcpPort uint16, direction Direction) *ReInviteState {
	s.VideoCodec = codec
	s.VideoRTPPort = rtpPort
	s.VideoRTCPPort = rtcpPort
	s.VideoDir = direction
	return s
}

// SetVideoFromAnswer is a convenience method for setting video state.
// RTCP port defaults to RTP port + 1.
func (s *ReInviteState) SetVideoFromAnswer(codec *Codec, rtpPort uint16, direction Direction) *ReInviteState {
	return s.SetVideo(codec, rtpPort, rtpPort+1, direction)
}

// SetBFCP stores the BFCP information from the initial offer and our local port.
// This will be used to include BFCP in re-INVITE with proper role reversal.
func (s *ReInviteState) SetBFCP(bfcpOffer *SDPBfcp, localPort uint16) *ReInviteState {
	s.BFCPInfo = bfcpOffer
	s.BFCPLocalPort = localPort
	return s
}

// HasAudio returns true if audio state has been set.
func (s *ReInviteState) HasAudio() bool {
	return s.AudioCodec != nil && s.AudioRTPPort > 0
}

// HasVideo returns true if video state has been set.
func (s *ReInviteState) HasVideo() bool {
	return s.VideoCodec != nil && s.VideoRTPPort > 0
}

// HasBFCP returns true if BFCP state has been set.
func (s *ReInviteState) HasBFCP() bool {
	return s.BFCPInfo != nil && s.BFCPLocalPort > 0
}

// BuildScreenshareReInvite builds a re-INVITE SDP for adding screenshare content.
// This preserves the existing audio and video m-lines while adding:
// - Screenshare video m-line with content:slides
// - BFCP m-line (if BFCP was in initial offer)
//
// The m-line order for Poly compatibility is: audio, video (main), BFCP, video (slides)
//
// Parameters:
//   - screenshareCodec: The H.264 codec to use for screenshare (typically PT 109)
//   - screenshareRTPPort: Local RTP port for screenshare
//   - screenshareRTCPPort: Local RTCP port for screenshare (0 = RTP+1)
//   - mstreamID: The BFCP media stream ID to link screenshare with floor (typically 3)
func (s *ReInviteState) BuildScreenshareReInvite(screenshareCodec *Codec, screenshareRTPPort, screenshareRTCPPort, mstreamID uint16) ([]byte, error) {
	if !s.HasVideo() {
		return nil, fmt.Errorf("video state not set - call SetVideo first")
	}

	// Use RTP+1 for RTCP if not specified
	if screenshareRTCPPort == 0 {
		screenshareRTCPPort = screenshareRTPPort + 1
	}

	// Build the re-INVITE config
	cfg := NewReInviteConfigForPoly(s.LocalAddr)

	// Always include audio if negotiated (THIS IS THE KEY FIX)
	if s.HasAudio() {
		cfg.WithAudio(s.AudioCodec, s.AudioRTPPort, s.AudioRTCPPort, s.AudioDir)
	}

	// Include video (camera) - required
	cfg.WithVideo(s.VideoCodec, s.VideoRTPPort, s.VideoRTCPPort, s.VideoDir)

	// Include screenshare - required for this method
	cfg.WithScreenshare(screenshareCodec, screenshareRTPPort, screenshareRTCPPort, DirectionSendOnly)

	// Include BFCP if available
	if s.HasBFCP() {
		// Use MStreamID to link BFCP floor to screenshare label
		actualMStreamID := mstreamID
		if actualMStreamID == 0 {
			actualMStreamID = 3 // Default BFCP mstream ID for content
		}
		cfg.WithBFCP(
			s.BFCPLocalPort,
			s.BFCPInfo.Proto,
			s.BFCPInfo.ConfID,
			s.BFCPInfo.UserID,
			s.BFCPInfo.FloorID,
			actualMStreamID,
		)
	}

	return cfg.Build()
}

// BuildScreenshareReInviteWithLabel is like BuildScreenshareReInvite but uses the
// BFCP MStreamID from the original offer if available.
func (s *ReInviteState) BuildScreenshareReInviteWithLabel(screenshareCodec *Codec, screenshareRTPPort, screenshareRTCPPort uint16) ([]byte, error) {
	mstreamID := uint16(3) // Default
	if s.BFCPInfo != nil && s.BFCPInfo.MStreamID > 0 {
		mstreamID = s.BFCPInfo.MStreamID
	}
	return s.BuildScreenshareReInvite(screenshareCodec, screenshareRTPPort, screenshareRTCPPort, mstreamID)
}

// ToReInviteConfig converts the state to a ReInviteConfig for manual customization.
// This allows callers to further modify the config before building.
func (s *ReInviteState) ToReInviteConfig() *ReInviteConfig {
	cfg := NewReInviteConfigForPoly(s.LocalAddr)

	if s.HasAudio() {
		cfg.WithAudio(s.AudioCodec, s.AudioRTPPort, s.AudioRTCPPort, s.AudioDir)
	}

	if s.HasVideo() {
		cfg.WithVideo(s.VideoCodec, s.VideoRTPPort, s.VideoRTCPPort, s.VideoDir)
	}

	return cfg
}

// Clone creates a deep copy of the state.
func (s *ReInviteState) Clone() *ReInviteState {
	if s == nil {
		return nil
	}
	clone := &ReInviteState{
		LocalAddr:     s.LocalAddr,
		AudioRTPPort:  s.AudioRTPPort,
		AudioRTCPPort: s.AudioRTCPPort,
		AudioDir:      s.AudioDir,
		VideoRTPPort:  s.VideoRTPPort,
		VideoRTCPPort: s.VideoRTCPPort,
		VideoDir:      s.VideoDir,
		BFCPLocalPort: s.BFCPLocalPort,
	}
	if s.AudioCodec != nil {
		clone.AudioCodec = s.AudioCodec.Clone()
	}
	if s.VideoCodec != nil {
		clone.VideoCodec = s.VideoCodec.Clone()
	}
	if s.BFCPInfo != nil {
		clone.BFCPInfo = s.BFCPInfo.Clone()
	}
	return clone
}
