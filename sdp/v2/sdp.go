package v2

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"

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

	for _, md := range sd.MediaDescriptions {
		sm := &SDPMedia{}
		if err := sm.FromPion(*md); err != nil {
			// Skip unsupported media kinds (e.g., "application" for BFCP, H224)
			// instead of failing the entire SDP parsing
			continue
		}
		switch sm.Kind {
		case MediaKindAudio:
			s.Audio = sm
		case MediaKindVideo:
			s.Video = sm
		default:
			// Skip unsupported media kinds
			continue
		}
	}

	return nil
}

func (s *SDP) ToPion() (sdp.SessionDescription, error) {
	sessId := rand.Uint64() // TODO: do we need to track these?

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
	}
	if s.Video != nil {
		videoMD, err := s.Video.ToPion()
		if err != nil {
			return sd, fmt.Errorf("failed to convert video media: %w", err)
		}
		sd.MediaDescriptions = append(sd.MediaDescriptions, &videoMD)
	}

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
