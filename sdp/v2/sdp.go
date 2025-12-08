package v2

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"strings"

	"github.com/pion/sdp/v3"
)

func NewSDP(sdpData []byte) (*SDP, error) {
	s := &SDP{}
	if err := s.Unmarshal(sdpData); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SDP) Unmarshal(sdpData []byte) error {
	var psdp sdp.SessionDescription
	if err := psdp.Unmarshal(sdpData); err != nil {
		return err
	}
	if err := s.FromPion(psdp); err != nil {
		return err
	}
	return nil
}

func (s *SDP) Marshal() ([]byte, error) {
	psdp, err := s.ToPion()
	if err != nil {
		return nil, err
	}
	return psdp.Marshal()
}

func (s *SDP) FromPion(sd sdp.SessionDescription) error {
	addr, err := netip.ParseAddr(sd.Origin.UnicastAddress)
	if err != nil {
		return err
	}
	s.Addr = addr

	slog.Debug("SDP FromPion: parsing session",
		"origin", sd.Origin.UnicastAddress,
		"sessionName", string(sd.SessionName),
		"mediaCount", len(sd.MediaDescriptions),
	)

	for i, md := range sd.MediaDescriptions {
		slog.Debug("SDP FromPion: media description",
			"index", i,
			"mediaName", md.MediaName.Media,
			"port", md.MediaName.Port.Value,
			"proto", md.MediaName.Protos,
			"formats", md.MediaName.Formats,
		)

		// Log all attributes for debugging (useful for BFCP)
		for _, attr := range md.Attributes {
			slog.Debug("SDP FromPion: media attribute",
				"index", i,
				"mediaName", md.MediaName.Media,
				"attrKey", attr.Key,
				"attrValue", attr.Value,
			)
		}

		// Check for BFCP media (application with BFCP protocol)
		if md.MediaName.Media == "application" {
			proto := strings.Join(md.MediaName.Protos, "/")
			if strings.Contains(strings.ToUpper(proto), "BFCP") {
				bfcp := &SDPBfcp{}
				if err := bfcp.FromPion(*md); err != nil {
					slog.Debug("SDP FromPion: skipping invalid BFCP",
						"index", i,
						"error", err.Error(),
					)
					continue
				}
				s.BFCP = bfcp
				slog.Debug("SDP FromPion: parsed BFCP media",
					"port", bfcp.Port,
					"proto", bfcp.Proto,
					"setup", bfcp.Setup,
					"floorctrl", bfcp.FloorCtrl,
				)
				continue
			}
		}

		sm := &SDPMedia{}
		if err := sm.FromPion(*md); err != nil {
			// Skip unsupported media kinds (e.g., "application" for H224)
			// instead of failing the entire SDP parsing
			slog.Debug("SDP FromPion: skipping unsupported media",
				"index", i,
				"mediaName", md.MediaName.Media,
				"error", err.Error(),
			)
			continue
		}
		switch sm.Kind {
		case MediaKindAudio:
			s.Audio = sm
			slog.Debug("SDP FromPion: parsed audio media",
				"port", sm.Port,
				"direction", sm.Direction,
				"codecCount", len(sm.Codecs),
			)
		case MediaKindVideo:
			// Check if this is screenshare (content:slides) or camera video
			if sm.Content == ContentTypeSlides {
				s.Screenshare = sm
				slog.Debug("SDP FromPion: parsed screenshare media",
					"port", sm.Port,
					"direction", sm.Direction,
					"content", sm.Content,
					"codecCount", len(sm.Codecs),
				)
			} else {
				s.Video = sm
				slog.Debug("SDP FromPion: parsed video media",
					"port", sm.Port,
					"direction", sm.Direction,
					"content", sm.Content,
					"codecCount", len(sm.Codecs),
				)
			}
		default:
			// Skip unsupported media kinds
			slog.Debug("SDP FromPion: skipping unknown media kind",
				"kind", sm.Kind,
			)
			continue
		}
	}

	return nil
}

func (s *SDP) ToPion() (sdp.SessionDescription, error) {
	sessId := rand.Uint64() // TODO: do we need to track these?

	slog.Debug("SDP ToPion: generating session",
		"addr", s.Addr.String(),
		"hasAudio", s.Audio != nil,
		"hasVideo", s.Video != nil,
		"hasScreenshare", s.Screenshare != nil,
		"hasBFCP", s.BFCP != nil,
	)

	sd := sdp.SessionDescription{
		Version: 0,
		Origin: sdp.Origin{
			Username:       "-",
			SessionID:      sessId,
			SessionVersion: sessId,
			NetworkType:    "IN",
			AddressType:    "IP4",
			UnicastAddress: s.Addr.String(),
		},
		SessionName: "LiveKit",
		ConnectionInformation: &sdp.ConnectionInformation{
			NetworkType: "IN",
			AddressType: "IP4",
			Address:     &sdp.Address{Address: s.Addr.String()},
		},
		TimeDescriptions: []sdp.TimeDescription{
			{
				Timing: sdp.Timing{
					StartTime: 0,
					StopTime:  0,
				},
			},
		},
	}
	if s.Audio != nil {
		audioMD, err := s.Audio.ToPion()
		if err != nil {
			return sd, fmt.Errorf("failed to convert audio media: %w", err)
		}
		sd.MediaDescriptions = append(sd.MediaDescriptions, &audioMD)
		slog.Debug("SDP ToPion: added audio media",
			"port", audioMD.MediaName.Port.Value,
			"proto", audioMD.MediaName.Protos,
		)
	}
	if s.Video != nil {
		videoMD, err := s.Video.ToPion()
		if err != nil {
			return sd, fmt.Errorf("failed to convert video media: %w", err)
		}
		sd.MediaDescriptions = append(sd.MediaDescriptions, &videoMD)
		slog.Debug("SDP ToPion: added video media",
			"port", videoMD.MediaName.Port.Value,
			"proto", videoMD.MediaName.Protos,
		)
	}
	if s.Screenshare != nil {
		screenshareMD, err := s.Screenshare.ToPion()
		if err != nil {
			return sd, fmt.Errorf("failed to convert screenshare media: %w", err)
		}
		sd.MediaDescriptions = append(sd.MediaDescriptions, &screenshareMD)
		slog.Debug("SDP ToPion: added screenshare media",
			"port", screenshareMD.MediaName.Port.Value,
			"proto", screenshareMD.MediaName.Protos,
			"content", s.Screenshare.Content,
		)
	}
	if s.BFCP != nil && !s.BFCP.Disabled {
		bfcpMD, err := s.BFCP.ToPion()
		if err != nil {
			return sd, fmt.Errorf("failed to convert BFCP media: %w", err)
		}
		sd.MediaDescriptions = append(sd.MediaDescriptions, &bfcpMD)
		slog.Debug("SDP ToPion: added BFCP media",
			"port", bfcpMD.MediaName.Port.Value,
			"proto", bfcpMD.MediaName.Protos,
		)
	}

	slog.Debug("SDP ToPion: complete",
		"mediaCount", len(sd.MediaDescriptions),
	)

	return sd, nil
}

func (s *SDP) Clone() *SDP {
	if s == nil {
		return nil
	}
	clone := &SDP{
		Addr: s.Addr,
	}
	if s.Audio != nil {
		clone.Audio = s.Audio.Clone()
	}
	if s.Video != nil {
		clone.Video = s.Video.Clone()
	}
	if s.Screenshare != nil {
		clone.Screenshare = s.Screenshare.Clone()
	}
	if s.BFCP != nil {
		clone.BFCP = s.BFCP.Clone()
	}
	return clone
}

func (s *SDP) Builder() *SDPBuilder {
	return &SDPBuilder{s: s.Clone()}
}

type SDPBuilder struct {
	errs []error
	s    *SDP
}

var _ interface {
	Builder[*SDP]
	SetAddress(netip.Addr) *SDPBuilder
	SetVideo(func(b *SDPMediaBuilder) (*SDPMedia, error)) *SDPBuilder
	SetAudio(func(b *SDPMediaBuilder) (*SDPMedia, error)) *SDPBuilder
	SetScreenshare(func(b *SDPMediaBuilder) (*SDPMedia, error)) *SDPBuilder
	SetBFCP(func(b *SDPBfcpBuilder) (*SDPBfcp, error)) *SDPBuilder
} = (*SDPBuilder)(nil)

func (b *SDPBuilder) Build() (*SDP, error) {
	if len(b.errs) > 0 {
		return nil, fmt.Errorf("failed to build SDP with %d errors: %w", len(b.errs), errors.Join(b.errs...))
	}
	return b.s, nil
}

func (b *SDPBuilder) SetAddress(addr netip.Addr) *SDPBuilder {
	b.s.Addr = addr
	return b
}

func (b *SDPBuilder) SetVideo(fn func(b *SDPMediaBuilder) (*SDPMedia, error)) *SDPBuilder {
	mb := &SDPMediaBuilder{m: &SDPMedia{}}
	mb.SetKind(MediaKindVideo)
	m, err := fn(mb)
	if err != nil {
		b.errs = append(b.errs, err)
		return b
	}
	b.s.Video = m
	return b
}

func (b *SDPBuilder) SetAudio(fn func(b *SDPMediaBuilder) (*SDPMedia, error)) *SDPBuilder {
	mb := &SDPMediaBuilder{m: &SDPMedia{}}
	mb.SetKind(MediaKindAudio)
	m, err := fn(mb)
	if err != nil {
		b.errs = append(b.errs, err)
		return b
	}
	b.s.Audio = m
	return b
}

func (b *SDPBuilder) SetScreenshare(fn func(b *SDPMediaBuilder) (*SDPMedia, error)) *SDPBuilder {
	mb := &SDPMediaBuilder{m: &SDPMedia{}}
	mb.SetKind(MediaKindVideo)
	mb.SetContent(ContentTypeSlides)
	m, err := fn(mb)
	if err != nil {
		b.errs = append(b.errs, err)
		return b
	}
	b.s.Screenshare = m
	return b
}

func (b *SDPBuilder) SetBFCP(fn func(b *SDPBfcpBuilder) (*SDPBfcp, error)) *SDPBuilder {
	bb := NewSDPBfcpBuilder()
	bfcp, err := fn(bb)
	if err != nil {
		b.errs = append(b.errs, err)
		return b
	}
	b.s.BFCP = bfcp
	return b
}
