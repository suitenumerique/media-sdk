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
	Addr        netip.Addr
	Audio       *SDPMedia
	Video       *SDPMedia
	Screenshare *SDPMedia // Video with content:slides attribute
	BFCP        *SDPBfcp  // BFCP floor control (RFC 8856)
}

var _ interface {
	Marshallable
	Clonable[*SDP]
	Buildable[*SDP, *SDPBuilder]
	FromPion(sdp.SessionDescription) error
	ToPion() (sdp.SessionDescription, error)
	V1MediaConfig(remote netip.AddrPort) (sdpv1.MediaConfig, error)
} = (*SDP)(nil)

// ContentType indicates the content type for video media (RFC 4796)
type ContentType string

const (
	ContentTypeMain   ContentType = "main"   // Primary video (camera)
	ContentTypeSlides ContentType = "slides" // Presentation/screenshare
	ContentTypeAlt    ContentType = "alt"    // Alternative video
)

// SDPMedia describes a single m= section while reusing pion's representation
// for raw attributes and payloads.
type SDPMedia struct {
	Kind      MediaKind   // Kind is the media type (audio, video, application, ...).
	Disabled  bool        // Disabled is true when the port is zero (rejected m=).
	Direction Direction   // Direction indicates the media flow direction.
	Content   ContentType // Content indicates the content type for video (RFC 4796: main, slides, alt)
	Label     uint16      // Label for BFCP floor association (RFC 4796, links to floorid mstrm:X)
	Codecs    []*Codec    // Codecs lists payload formats mapped onto media.Codec entries.
	Codec     *Codec      // PreferredCodec is the selected codec for this track.
	Security  Security    // Security captures SRTP profiles signaled for the media section.
	Port      uint16      // Port is the media port from the m= line.
	RTCPPort  uint16      // RTCPPort is the RTCP port from the m= line. (0 mean not specified)
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

// BfcpProto represents the BFCP transport protocol
type BfcpProto string

const (
	BfcpProtoTCP    BfcpProto = "TCP/BFCP"
	BfcpProtoTCPTLS BfcpProto = "TCP/TLS/BFCP"
)

// BfcpSetup represents the BFCP connection setup role (RFC 4145 / RFC 8856)
type BfcpSetup string

const (
	BfcpSetupActive  BfcpSetup = "active"
	BfcpSetupPassive BfcpSetup = "passive"
	BfcpSetupActpass BfcpSetup = "actpass"
)

// Reverse returns the opposite setup role for SDP answer generation
func (s BfcpSetup) Reverse() BfcpSetup {
	switch s {
	case BfcpSetupActive:
		return BfcpSetupPassive
	case BfcpSetupPassive:
		return BfcpSetupActive
	case BfcpSetupActpass:
		return BfcpSetupPassive // actpass answerer typically chooses passive
	default:
		return s
	}
}

// BfcpConnection represents the SDP connection attribute for BFCP
type BfcpConnection string

const (
	BfcpConnectionNew      BfcpConnection = "new"
	BfcpConnectionExisting BfcpConnection = "existing"
)

// BfcpFloorCtrl represents the floor control role in BFCP
type BfcpFloorCtrl string

const (
	BfcpFloorCtrlClient BfcpFloorCtrl = "c-only" // Client only
	BfcpFloorCtrlServer BfcpFloorCtrl = "s-only" // Server only
	BfcpFloorCtrlBoth   BfcpFloorCtrl = "c-s"    // Both roles
)

// Reverse returns the opposite floor control role for SDP answer generation
func (f BfcpFloorCtrl) Reverse() BfcpFloorCtrl {
	switch f {
	case BfcpFloorCtrlClient:
		return BfcpFloorCtrlServer
	case BfcpFloorCtrlServer:
		return BfcpFloorCtrlClient
	case BfcpFloorCtrlBoth:
		return BfcpFloorCtrlServer // c-s answerer typically becomes server
	default:
		return f
	}
}

// SDPBfcp describes a BFCP m=application section (RFC 8856)
type SDPBfcp struct {
	Disabled   bool           // Disabled is true when the port is zero (rejected m=)
	Port       uint16         // Media port from m= line
	Proto      BfcpProto      // Protocol: TCP/BFCP or TCP/TLS/BFCP
	Setup      BfcpSetup      // Connection setup role (active/passive/actpass)
	Connection BfcpConnection // Connection reuse policy (new/existing)
	FloorCtrl  BfcpFloorCtrl  // Floor control role (c-only/s-only/c-s)
	ConfID     uint32         // Conference ID
	UserID     uint32         // User ID
	FloorID    uint16         // Floor ID
	MStreamID  uint16         // Media stream association (from floorid mstrm:X)
}

var _ interface {
	Clonable[*SDPBfcp]
	Buildable[*SDPBfcp, *SDPBfcpBuilder]
} = (*SDPBfcp)(nil)
