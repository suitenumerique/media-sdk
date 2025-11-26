package v2

import (
	"net/netip"

	"github.com/pion/sdp/v3"

	media "github.com/livekit/media-sdk"
	sdpv1 "github.com/livekit/media-sdk/sdp"
	"github.com/livekit/media-sdk/srtp"
)

// SDP wraps a pion SessionDescription and the interpreted media sections.
// The raw SDP remains available for round-tripping while Media holds
// higher-level details extracted from each m= block.
type SDP struct {
	Addr  netip.Addr
	Audio *SDPMedia
	Video *SDPMedia
}

var _ interface {
	Marshallable
	Clonable[*SDP]
	Buildable[*SDP, *SDPBuilder]
	FromPion(sdp.SessionDescription) error
	ToPion() (sdp.SessionDescription, error)
	V1MediaConfig(remote netip.AddrPort) (sdpv1.MediaConfig, error)
} = (*SDP)(nil)

// SDPMedia describes a single m= section while reusing pion's representation
// for raw attributes and payloads.
type SDPMedia struct {
	Kind      MediaKind // Kind is the media type (audio, video, application, ...).
	Disabled  bool      // Disabled is true when the port is zero (rejected m=).
	Direction Direction // Direction indicates the media flow direction.
	Codecs    []*Codec  // Codecs lists payload formats mapped onto media.Codec entries.
	Codec     *Codec    // PreferredCodec is the selected codec for this track.
	Security  Security  // Security captures SRTP profiles signaled for the media section.
	Port      uint16    // Port is the media port from the m= line.
	RTCPPort  uint16    // RTCPPort is the RTCP port from the m= line. (0 mean not specified)
}

var _ interface {
	FromPion(sdp.MediaDescription) error
	ToPion() (sdp.MediaDescription, error)
	Clonable[*SDPMedia]
	Buildable[*SDPMedia, *SDPMediaBuilder]
	SelectCodec() error
} = (*SDPMedia)(nil)

// MediaKind is a simple string alias for the SDP media name.
type MediaKind string

const (
	MediaKindAudio       MediaKind = "audio"
	MediaKindVideo       MediaKind = "video"
	MediaKindApplication MediaKind = "application"
	MediaKindData        MediaKind = "data"
)

func ToMediaKind(s string) (MediaKind, bool) {
	switch s {
	case "audio":
		return MediaKindAudio, true
	case "video":
		return MediaKindVideo, true
	case "application":
		return MediaKindApplication, true
	case "data":
		return MediaKindData, true
	default:
		return MediaKindAudio, false
	}
}

type Direction string

const (
	DirectionSendRecv Direction = "sendrecv"
	DirectionSendOnly Direction = "sendonly"
	DirectionRecvOnly Direction = "recvonly"
	DirectionInactive Direction = "inactive"
)

func (d Direction) IsSend() bool {
	return d == DirectionSendRecv || d == DirectionSendOnly
}

func (d Direction) IsRecv() bool {
	return d == DirectionSendRecv || d == DirectionRecvOnly
}

func (d Direction) Reverse() Direction {
	switch d {
	case DirectionSendOnly:
		return DirectionRecvOnly
	case DirectionRecvOnly:
		return DirectionSendOnly
	default:
		return d
	}
}

// Codec ties a payload type to a media.Codec while retaining SDP fmtp/rtcp-fb data.
type Codec struct {
	PayloadType uint8
	Name        string
	Codec       media.Codec
	ClockRate   uint32
	FMTP        map[string]string
	RTCPFB      []sdp.Attribute
}

var _ interface {
	Clonable[*Codec]
	Buildable[*Codec, *CodecBuilder]
} = (*Codec)(nil)

// MediaSection still exposes the raw pion attributes via Description.Attributes,
// so additional data such as ICE/DTLS parameters can be retrieved on demand.

// Security keeps track of SRTP negotiation details.
type Security struct {
	Mode     sdpv1.Encryption
	Profiles []srtp.Profile
}
