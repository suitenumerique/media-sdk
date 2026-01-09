package v2

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	media "github.com/livekit/media-sdk"
	"github.com/livekit/media-sdk/rtp"
	v1 "github.com/livekit/media-sdk/sdp"
	"github.com/livekit/media-sdk/srtp"
	"github.com/pion/sdp/v3"
)

// SelectCodec finds the best codec according to priority rules set by Codec.Info().Priority.
// For H264, it prefers packetization-mode=1 over mode=0 for proper RTP fragmentation.
func (m *SDPMedia) SelectCodec() error {
	if m.Disabled || len(m.Codecs) == 0 {
		return nil
	}

	var bestCodec *Codec
	var bestPriority int

	for _, codec := range m.Codecs {
		if codec.Codec == nil {
			continue
		}

		info := codec.Codec.Info()
		priority := info.Priority

		// Prefer H264 with packetization-mode=1 for proper RTP fragmentation
		if strings.Contains(info.SDPName, "H264") {
			if mode, ok := codec.FMTP["packetization-mode"]; ok && mode == "1" {
				priority += 10
			}
		}

		if bestCodec == nil || priority > bestPriority {
			bestCodec = codec
			bestPriority = priority
		}
	}

	if bestCodec == nil {
		return fmt.Errorf("no valid codec found for media kind %s: %w", m.Kind, v1.ErrNoCommonMedia)
	}

	m.Codec = bestCodec
	return nil
}

func (m *SDPMedia) Clone() *SDPMedia {
	return &SDPMedia{
		Kind:      m.Kind,
		Disabled:  m.Disabled,
		Direction: m.Direction,
		Content:   m.Content,
		Label:     m.Label,
		Codecs: func() []*Codec {
			if m.Codecs == nil {
				return nil
			}
			codecs := make([]*Codec, len(m.Codecs))
			for i, c := range m.Codecs {
				codecs[i] = c.Clone()
			}
			return codecs
		}(),
		Codec: func() *Codec {
			if m.Codec == nil {
				return nil
			}
			return m.Codec.Clone()
		}(),
		Security: Security{
			Profiles: func() []srtp.Profile {
				if m.Security.Profiles == nil {
					return nil
				}
				profiles := make([]srtp.Profile, len(m.Security.Profiles))
				copy(profiles, m.Security.Profiles)
				return profiles
			}(),
			Mode: m.Security.Mode,
		},
		Port:     m.Port,
		RTCPPort: m.RTCPPort,
	}
}

func (m *SDPMedia) parseArributes(md sdp.MediaDescription) error {
	var rtcpPort uint16
	type trackInfo struct {
		codec  *Codec
		rtcpFb []sdp.Attribute
		fmtp   map[string]string
	}
	tracks := make(map[uint8]trackInfo)

	m.Direction = DirectionSendRecv // Default direction

	for _, attr := range md.Attributes {
		switch attr.Key {
		case "rtpmap":
			sub := strings.SplitN(attr.Value, " ", 2)
			if len(sub) != 2 {
				continue
			}
			typ, err := strconv.Atoi(sub[0])
			if err != nil {
				continue
			}
			if typ < 0 || typ > 255 {
				continue
			}
			name := sub[1]
			codec := v1.CodecByName(name)
			if codec == nil {
				continue
			}

			c, err := (&Codec{}).Builder().SetPayloadType(uint8(typ)).SetCodec(codec).Build()
			if err != nil {
				continue
			}

			ti := tracks[uint8(typ)]
			ti.codec = c
			tracks[uint8(typ)] = ti
		case "fmtp":
			sub := strings.SplitN(attr.Value, " ", 2)
			if len(sub) != 2 {
				continue
			}
			typ, err := strconv.Atoi(sub[0])
			if err != nil {
				continue
			}
			if typ < 0 || typ > 255 {
				continue
			}
			params := strings.Split(sub[1], ";")
			fmtp := make(map[string]string)
			for _, p := range params {
				kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
				if len(kv) != 2 {
					continue
				}
				fmtp[kv[0]] = kv[1]
			}

			ti := tracks[uint8(typ)]
			ti.fmtp = fmtp
			tracks[uint8(typ)] = ti
		case "rtcp":
			sub := strings.SplitN(attr.Value, " ", 2)
			portStr := sub[0]
			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}
			if port < 0 || port > 65535 {
				continue
			}
			rtcpPort = uint16(port)
		case "rtcp-fb":
			sub := strings.SplitN(attr.Value, " ", 2)
			if len(sub) != 2 {
				continue
			}
			// Handle wildcard rtcp-fb (applies to all payload types)
			if sub[0] == "*" {
				for pt := range tracks {
					ti := tracks[pt]
					ti.rtcpFb = append(ti.rtcpFb, sdp.Attribute{
						Key:   "rtcp-fb",
						Value: attr.Value,
					})
					tracks[pt] = ti
				}
				continue
			}
			typ, err := strconv.Atoi(sub[0])
			if err != nil {
				continue
			}
			if typ < 0 || typ > 255 {
				continue
			}
			ti := tracks[uint8(typ)]
			ti.rtcpFb = append(ti.rtcpFb, sdp.Attribute{
				Key:   "rtcp-fb",
				Value: attr.Value,
			})
			tracks[uint8(typ)] = ti
		case
			string(DirectionSendRecv),
			string(DirectionSendOnly),
			string(DirectionRecvOnly),
			string(DirectionInactive):
			m.Direction = Direction(attr.Key)
		case "content":
			// RFC 4796 content attribute (main, slides, alt, etc.)
			m.Content = ContentType(attr.Value)
		case "label":
			// RFC 4796 label attribute for BFCP floor association
			label, err := strconv.Atoi(attr.Value)
			if err == nil && label >= 0 && label <= 65535 {
				m.Label = uint16(label)
			}
		default:
			// Ignore unknown attributes for now
		}
	}

	for _, ti := range tracks {
		if ti.codec == nil {
			continue
		}
		ti.codec.FMTP = ti.fmtp
		ti.codec.RTCPFB = ti.rtcpFb
		m.Codecs = append(m.Codecs, ti.codec)
	}

	if rtcpPort != 0 {
		m.RTCPPort = rtcpPort
	} else {
		m.RTCPPort = m.Port + 1
	}

	return nil
}

func (m *SDPMedia) FromPion(md sdp.MediaDescription) error {
	mkind, ok := ToMediaKind(md.MediaName.Media)
	if !ok {
		return fmt.Errorf("unsupported media kind: %s", md.MediaName.Media)
	}
	m.Kind = mkind

	m.Port = uint16(md.MediaName.Port.Value)

	if m.Port == 0 {
		m.Disabled = true
	}

	m.parseArributes(md)

	for _, f := range md.MediaName.Formats {
		pt, err := strconv.Atoi(f)
		if err != nil {
			continue
		}
		if pt < 0 || pt > 255 {
			continue
		}
		codec := rtp.CodecByPayloadType(byte(pt))
		if codec == nil {
			continue
		}
		c, err := (&Codec{}).Builder().SetPayloadType(uint8(pt)).SetCodec(codec).Build()
		if err != nil {
			continue
		}
		m.Codecs = append(m.Codecs, c)
	}

	return nil
}

func (m *SDPMedia) ToPion() (sdp.MediaDescription, error) {
	// Static compiler check for frame duration hardcoded below.
	var _ = [1]struct{}{}[20*time.Millisecond-media.DefFrameDur]
	formats := make([]string, 0, len(m.Codecs))
	attrs := []sdp.Attribute{}

	for _, codec := range m.Codecs {
		styp := strconv.Itoa(int(codec.PayloadType))
		formats = append(formats, styp)
		attrs = append(attrs, sdp.Attribute{
			Key: "rtpmap", Value: styp + " " + codec.Codec.Info().SDPName,
		})

		if len(codec.FMTP) > 0 {
			attrs = append(attrs, sdp.Attribute{
				Key:   "fmtp",
				Value: styp + " " + strings.Join(codec.FmtpParts(), "; "),
			})
		}

		if len(codec.RTCPFB) > 0 {
			attrs = append(attrs, sdp.Attribute{
				Key: "rtcp-fb",
				Value: strings.Join(func() []string {
					parts := make([]string, 0, len(codec.RTCPFB))
					for _, fb := range codec.RTCPFB {
						parts = append(parts, fb.Value)
					}
					return parts
				}(), " "),
			})
		}
	}

	if m.RTCPPort != 0 {
		attrs = append(attrs, sdp.Attribute{
			Key: "rtcp", Value: strconv.Itoa(int(m.RTCPPort)),
		})
	}
	// RFC 4796
	if m.Content != "" {
		attrs = append(attrs, sdp.Attribute{
			Key: "content", Value: string(m.Content),
		})
	}
	// RFC 4796
	if m.Label > 0 {
		attrs = append(attrs, sdp.Attribute{
			Key: "label", Value: strconv.Itoa(int(m.Label)),
		})
	}
	dir := m.Direction
	if dir == "" {
		dir = DirectionSendRecv
	}
	attrs = append(attrs, []sdp.Attribute{
		{Key: "ptime", Value: "20"},
		{Key: string(dir)},
	}...)

	md := sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   string(m.Kind),
			Port:    sdp.RangedPort{Value: int(m.Port)},
			Protos:  []string{"RTP", "AVP"},
			Formats: formats,
		},
		Attributes: attrs,
	}

	return md, nil
}

func (m *SDPMedia) Builder() *SDPMediaBuilder {
	return &SDPMediaBuilder{m: m.Clone()}
}

type SDPMediaBuilder struct {
	errs []error
	m    *SDPMedia
}

var _ interface {
	Builder[*SDPMedia]
	SetRTPPort(port uint16) *SDPMediaBuilder
	SetRTCPPort(port uint16) *SDPMediaBuilder
	SetDisabled(disabled bool) *SDPMediaBuilder
	AddCodec(fn func(b *CodecBuilder) (*Codec, error), prefered bool) *SDPMediaBuilder
	SetSecurity(security Security) *SDPMediaBuilder
	SetDirection(direction Direction) *SDPMediaBuilder
	SetKind(kind MediaKind) *SDPMediaBuilder
} = (*SDPMediaBuilder)(nil)

func (b *SDPMediaBuilder) Build() (*SDPMedia, error) {
	if len(b.errs) > 0 {
		return nil, fmt.Errorf("failed to build SDPMedia with %d errors: %w", len(b.errs), errors.Join(b.errs...))
	}
	if b.m.Direction == "" {
		b.m.Direction = DirectionSendRecv
	}
	return b.m, nil
}

func (b *SDPMediaBuilder) SetRTPPort(port uint16) *SDPMediaBuilder {
	b.m.Port = port
	return b
}

func (b *SDPMediaBuilder) SetRTCPPort(port uint16) *SDPMediaBuilder {
	b.m.RTCPPort = port
	return b
}

func (b *SDPMediaBuilder) SetDisabled(disabled bool) *SDPMediaBuilder {
	b.m.Disabled = disabled
	return b
}

func (b *SDPMediaBuilder) AddCodec(fn func(b *CodecBuilder) (*Codec, error), prefered bool) *SDPMediaBuilder {
	c := &Codec{}
	cb := c.Builder()
	c, err := fn(cb)
	if err != nil {
		b.errs = append(b.errs, err)
		return b
	}
	b.m.Codecs = append(b.m.Codecs, c)
	if prefered {
		b.m.Codec = c
	}
	return b
}

func (b *SDPMediaBuilder) SetSecurity(security Security) *SDPMediaBuilder {
	panic("not implemented")
}

func (b *SDPMediaBuilder) SetDirection(direction Direction) *SDPMediaBuilder {
	b.m.Direction = direction
	return b
}

func (b *SDPMediaBuilder) SetKind(kind MediaKind) *SDPMediaBuilder {
	b.m.Kind = kind
	return b
}

func (b *SDPMediaBuilder) SetContent(content ContentType) *SDPMediaBuilder {
	b.m.Content = content
	return b
}

func (b *SDPMediaBuilder) SetLabel(label uint16) *SDPMediaBuilder {
	b.m.Label = label
	return b
}

// PrepareForSending prepares an SDPMedia answer for sending data.
// This is called after receiving an SDP answer when we want to send media to the remote.
// It performs:
// 1. Codec selection if not already set (picks first codec from Codecs list)
// 2. Direction reversal (recvonly in answer means we sendonly)
//
// The remote's answer says "recvonly" (they will receive), so from our perspective
// we need "sendonly" (we will send). This method handles that transformation.
func (m *SDPMedia) PrepareForSending() error {
	if m == nil || m.Disabled {
		return nil
	}

	// Select a codec if not already selected
	if m.Codec == nil && len(m.Codecs) > 0 {
		m.Codec = m.Codecs[0]
	}

	if m.Codec == nil {
		return fmt.Errorf("no codec available for sending")
	}

	// Reverse direction: if remote says recvonly (they receive), we sendonly (we send)
	m.Direction = m.Direction.Reverse()

	return nil
}

// NewScreenshareMediaFromCodec creates a screenshare SDPMedia using the given codec.
// This preserves the codec's PayloadType for compatibility with SIP devices that
// require consistent payload types between camera and content streams.
func NewScreenshareMediaFromCodec(codec *Codec, rtpPort, rtcpPort uint16, label uint16) *SDPMedia {
	c := codec.Clone()
	return &SDPMedia{
		Kind:      MediaKindVideo,
		Content:   ContentTypeSlides,
		Direction: DirectionSendOnly,
		Label:     label,
		Codec:     c,
		Codecs:    []*Codec{c},
		Port:      rtpPort,
		RTCPPort:  rtcpPort,
	}
}
