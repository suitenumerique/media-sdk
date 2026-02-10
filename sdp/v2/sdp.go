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

// hasBFCPAttributes checks if an application m-line has BFCP-specific attributes
// (floorid + floorctrl) regardless of protocol.
func hasBFCPAttributes(attrs []sdp.Attribute) bool {
	hasFloorID := false
	hasFloorCtrl := false
	for _, attr := range attrs {
		switch attr.Key {
		case "floorid":
			hasFloorID = true
		case "floorctrl":
			hasFloorCtrl = true
		}
	}
	return hasFloorID && hasFloorCtrl
}

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

	// Initialize m-line order tracking
	s.MLineOrder = make([]MLineType, 0, len(sd.MediaDescriptions))
	s.UnknownMedia = nil

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

		// Check for BFCP media (application with BFCP protocol or BFCP attributes)
		if md.MediaName.Media == "application" {
			proto := strings.Join(md.MediaName.Protos, "/")
			isBFCPProto := strings.Contains(strings.ToUpper(proto), "BFCP")
			isBFCPAttrs := !isBFCPProto && hasBFCPAttributes(md.Attributes)

			if isBFCPProto || isBFCPAttrs {
				bfcp := &SDPBfcp{}
				if err := bfcp.FromPion(*md); err != nil {
					slog.Debug("SDP FromPion: skipping invalid BFCP",
						"index", i,
						"error", err.Error(),
					)
					// Store as unknown m-line placeholder
					s.MLineOrder = append(s.MLineOrder, MLineUnknown)
					s.UnknownMedia = append(s.UnknownMedia, &SDPMedia{
						Kind:     MediaKindApplication,
						Disabled: true,
						Port:     0,
					})
					continue
				}
				s.BFCP = bfcp
				s.MLineOrder = append(s.MLineOrder, MLineBFCP)
				slog.Debug("SDP FromPion: parsed BFCP media",
					"port", bfcp.Port,
					"proto", bfcp.Proto,
					"setup", bfcp.Setup,
					"floorctrl", bfcp.FloorCtrl,
					"detectedByAttrs", isBFCPAttrs,
				)
				continue
			}
			// Non-BFCP application (e.g., H224) — store as unknown m-line
			slog.Debug("SDP FromPion: storing unknown application media",
				"index", i,
				"proto", proto,
			)
			s.MLineOrder = append(s.MLineOrder, MLineUnknown)
			s.UnknownMedia = append(s.UnknownMedia, &SDPMedia{
				Kind:     MediaKindApplication,
				Disabled: true,
				Port:     0,
			})
			continue
		}

		sm := &SDPMedia{}
		if err := sm.FromPion(*md); err != nil {
			// Store unsupported media as unknown m-line placeholder
			slog.Debug("SDP FromPion: storing unsupported media as unknown",
				"index", i,
				"mediaName", md.MediaName.Media,
				"error", err.Error(),
			)
			s.MLineOrder = append(s.MLineOrder, MLineUnknown)
			s.UnknownMedia = append(s.UnknownMedia, &SDPMedia{
				Kind:     MediaKind(md.MediaName.Media),
				Disabled: true,
				Port:     0,
			})
			continue
		}
		switch sm.Kind {
		case MediaKindAudio:
			s.Audio = sm
			s.MLineOrder = append(s.MLineOrder, MLineAudio)
			slog.Debug("SDP FromPion: parsed audio media",
				"port", sm.Port,
				"direction", sm.Direction,
				"codecCount", len(sm.Codecs),
			)
		case MediaKindVideo:
			// Check if this is screenshare (content:slides) or camera video
			if sm.Content == ContentTypeSlides {
				s.Screenshare = sm
				s.MLineOrder = append(s.MLineOrder, MLineScreenshare)
				slog.Debug("SDP FromPion: parsed screenshare media",
					"port", sm.Port,
					"direction", sm.Direction,
					"content", sm.Content,
					"codecCount", len(sm.Codecs),
				)
			} else {
				s.Video = sm
				s.MLineOrder = append(s.MLineOrder, MLineVideo)
				slog.Debug("SDP FromPion: parsed video media",
					"port", sm.Port,
					"direction", sm.Direction,
					"content", sm.Content,
					"codecCount", len(sm.Codecs),
				)
			}
		default:
			// Store unsupported media kinds as unknown
			slog.Debug("SDP FromPion: storing unknown media kind",
				"kind", sm.Kind,
			)
			s.MLineOrder = append(s.MLineOrder, MLineUnknown)
			s.UnknownMedia = append(s.UnknownMedia, sm)
			continue
		}
	}

	slog.Debug("SDP FromPion: complete",
		"mlineOrder", s.MLineOrder,
		"unknownCount", len(s.UnknownMedia),
	)

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
		"mlineOrder", s.MLineOrder,
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

	// Emit m-lines in the specified order (RFC 3264)
	if len(s.MLineOrder) > 0 {
		// Track which media types have been added
		addedAudio := false
		addedVideo := false
		addedScreenshare := false
		addedBFCP := false

		unknownIdx := 0
		for _, mtype := range s.MLineOrder {
			switch mtype {
			case MLineAudio:
				if s.Audio != nil {
					audioMD, err := s.Audio.ToPion()
					if err != nil {
						return sd, fmt.Errorf("failed to convert audio media: %w", err)
					}
					sd.MediaDescriptions = append(sd.MediaDescriptions, &audioMD)
					addedAudio = true
					slog.Debug("SDP ToPion: added audio media (ordered)",
						"port", audioMD.MediaName.Port.Value,
						"proto", audioMD.MediaName.Protos,
					)
				}
			case MLineVideo:
				if s.Video != nil {
					videoMD, err := s.Video.ToPion()
					if err != nil {
						return sd, fmt.Errorf("failed to convert video media: %w", err)
					}
					sd.MediaDescriptions = append(sd.MediaDescriptions, &videoMD)
					addedVideo = true
					slog.Debug("SDP ToPion: added video media (ordered)",
						"port", videoMD.MediaName.Port.Value,
						"proto", videoMD.MediaName.Protos,
					)
				}
			case MLineScreenshare:
				if s.Screenshare != nil {
					screenshareMD, err := s.Screenshare.ToPion()
					if err != nil {
						return sd, fmt.Errorf("failed to convert screenshare media: %w", err)
					}
					sd.MediaDescriptions = append(sd.MediaDescriptions, &screenshareMD)
					addedScreenshare = true
					slog.Debug("SDP ToPion: added screenshare media (ordered)",
						"port", screenshareMD.MediaName.Port.Value,
						"proto", screenshareMD.MediaName.Protos,
						"content", s.Screenshare.Content,
					)
				}
			case MLineBFCP:
				if s.BFCP != nil && !s.BFCP.Disabled {
					bfcpMD, err := s.BFCP.ToPion()
					if err != nil {
						return sd, fmt.Errorf("failed to convert BFCP media: %w", err)
					}
					sd.MediaDescriptions = append(sd.MediaDescriptions, &bfcpMD)
					addedBFCP = true
					slog.Debug("SDP ToPion: added BFCP media (ordered)",
						"port", bfcpMD.MediaName.Port.Value,
						"proto", bfcpMD.MediaName.Protos,
					)
				}
			case MLineUnknown:
				// Rejected m-line with port=0
				if unknownIdx < len(s.UnknownMedia) {
					um := s.UnknownMedia[unknownIdx]
					unknownIdx++
					rejectedMD, err := um.ToPion()
					if err != nil {
						slog.Debug("SDP ToPion: skipping unknown media due to error",
							"error", err.Error(),
						)
						continue
					}
					// Ensure port is 0 for rejected media
					rejectedMD.MediaName.Port.Value = 0
					sd.MediaDescriptions = append(sd.MediaDescriptions, &rejectedMD)
					slog.Debug("SDP ToPion: added rejected media (ordered)",
						"kind", um.Kind,
						"port", 0,
					)
				}
			}
		}

		// Append any media not already included in the ordered list
		if s.Audio != nil && !addedAudio {
			audioMD, err := s.Audio.ToPion()
			if err == nil {
				sd.MediaDescriptions = append(sd.MediaDescriptions, &audioMD)
				slog.Debug("SDP ToPion: added audio media (extra)",
					"port", audioMD.MediaName.Port.Value,
				)
			}
		}
		if s.Video != nil && !addedVideo {
			videoMD, err := s.Video.ToPion()
			if err == nil {
				sd.MediaDescriptions = append(sd.MediaDescriptions, &videoMD)
				slog.Debug("SDP ToPion: added video media (extra)",
					"port", videoMD.MediaName.Port.Value,
				)
			}
		}
		if s.Screenshare != nil && !addedScreenshare {
			screenshareMD, err := s.Screenshare.ToPion()
			if err == nil {
				sd.MediaDescriptions = append(sd.MediaDescriptions, &screenshareMD)
				slog.Debug("SDP ToPion: added screenshare media (extra)",
					"port", screenshareMD.MediaName.Port.Value,
					"content", s.Screenshare.Content,
				)
			}
		}
		if s.BFCP != nil && !s.BFCP.Disabled && !addedBFCP {
			bfcpMD, err := s.BFCP.ToPion()
			if err == nil {
				sd.MediaDescriptions = append(sd.MediaDescriptions, &bfcpMD)
				slog.Debug("SDP ToPion: added BFCP media (extra)",
					"port", bfcpMD.MediaName.Port.Value,
				)
			}
		}
	} else {
		// Default order: audio, video, screenshare, BFCP
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
	// Clone MLineOrder slice
	if len(s.MLineOrder) > 0 {
		clone.MLineOrder = make([]MLineType, len(s.MLineOrder))
		copy(clone.MLineOrder, s.MLineOrder)
	}
	// Clone UnknownMedia slice
	if len(s.UnknownMedia) > 0 {
		clone.UnknownMedia = make([]*SDPMedia, len(s.UnknownMedia))
		for i, um := range s.UnknownMedia {
			clone.UnknownMedia[i] = um.Clone()
		}
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

// SetMLineOrder sets the m-line output order for SDP generation (RFC 3264).
func (b *SDPBuilder) SetMLineOrder(order []MLineType) *SDPBuilder {
	if len(order) > 0 {
		b.s.MLineOrder = make([]MLineType, len(order))
		copy(b.s.MLineOrder, order)
	}
	return b
}

// SetUnknownMedia sets the rejected/unknown m-line placeholders (port=0).
func (b *SDPBuilder) SetUnknownMedia(media []*SDPMedia) *SDPBuilder {
	if len(media) > 0 {
		b.s.UnknownMedia = make([]*SDPMedia, len(media))
		for i, m := range media {
			b.s.UnknownMedia[i] = m.Clone()
		}
	}
	return b
}
