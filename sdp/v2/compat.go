package v2

import (
	"net/netip"
	"strings"

	"github.com/livekit/media-sdk/rtp"
	v1 "github.com/livekit/media-sdk/sdp"
	"github.com/livekit/media-sdk/srtp"
)

// V1MediaConfig converts the SDP to a v1 MediaConfig structure.
// It only contain audio as video support was added in v2.
func (s *SDP) V1MediaConfig(remote netip.AddrPort) (v1.MediaConfig, error) {
	var cfg v1.MediaConfig

	if s.Audio == nil {
		return cfg, v1.ErrNoCommonMedia
	}

	audio := s.Audio
	if audio.Disabled {
		return cfg, v1.ErrNoCommonMedia
	}

	if audio.Codec == nil || audio.Codec.Codec == nil {
		return cfg, v1.ErrNoCommonMedia
	}

	// Convert audio codec
	audioCodec, ok := audio.Codec.Codec.(rtp.AudioCodec)
	if !ok {
		return cfg, v1.ErrNoCommonMedia
	}

	cfg.Audio = v1.AudioConfig{
		Codec:    audioCodec,
		Type:     audio.Codec.PayloadType,
		DTMFType: 0, // Will be set if DTMF codec is found
	}

	// Look for DTMF codec
	for _, codec := range audio.Codecs {
		if strings.HasPrefix(codec.Name, "telephone-event") {
			cfg.Audio.DTMFType = codec.PayloadType
			break
		}
	}

	if s.Addr.IsValid() {
		cfg.Local = netip.AddrPortFrom(s.Addr, audio.Port)
	}

	cfg.Remote = remote

	// Convert crypto
	if len(audio.Security.Profiles) > 0 {
		// Select the first profile for now
		// In a real negotiation, this would be matched against offer
		profile := audio.Security.Profiles[0]
		sp, err := profile.Profile.Parse()
		if err != nil {
			return cfg, err
		}

		cfg.Crypto = &srtp.Config{
			Profile: sp,
			Keys: srtp.SessionKeys{
				LocalMasterKey:   profile.Key,
				LocalMasterSalt:  profile.Salt,
				RemoteMasterKey:  nil, // Will be set during negotiation
				RemoteMasterSalt: nil,
			},
		}
	}

	return cfg, nil
}
