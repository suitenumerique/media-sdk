package v2

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/pion/sdp/v3"
)

// FromPion parses BFCP attributes from a pion MediaDescription.
func (b *SDPBfcp) FromPion(md sdp.MediaDescription) error {
	if md.MediaName.Media != "application" {
		return fmt.Errorf("expected application media, got %s", md.MediaName.Media)
	}

	proto := strings.Join(md.MediaName.Protos, "/")
	if !strings.Contains(strings.ToUpper(proto), "BFCP") {
		return fmt.Errorf("expected BFCP protocol, got %s", proto)
	}

	b.Port = uint16(md.MediaName.Port.Value)
	b.Disabled = b.Port == 0
	b.Proto = BfcpProto(proto)

	for _, attr := range md.Attributes {
		switch attr.Key {
		case "setup":
			b.Setup = BfcpSetup(attr.Value)
		case "connection":
			b.Connection = BfcpConnection(attr.Value)
		case "floorctrl":
			b.FloorCtrl = BfcpFloorCtrl(attr.Value)
		case "confid":
			if v, err := strconv.ParseUint(attr.Value, 10, 32); err == nil {
				b.ConfID = uint32(v)
			}
		case "userid":
			if v, err := strconv.ParseUint(attr.Value, 10, 32); err == nil {
				b.UserID = uint32(v)
			}
		case "floorid":
			b.parseFloorID(attr.Value)
		}
	}

	return nil
}

// parseFloorID parses the floorid attribute value.
// Format: "N" or "N mstrm:M"
func (b *SDPBfcp) parseFloorID(value string) {
	parts := strings.Fields(value)
	if len(parts) >= 1 {
		if v, err := strconv.ParseUint(parts[0], 10, 16); err == nil {
			b.FloorID = uint16(v)
		}
	}
	if len(parts) >= 2 && strings.HasPrefix(parts[1], "mstrm:") {
		if v, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "mstrm:"), 10, 16); err == nil {
			b.MStreamID = uint16(v)
		}
	}
}

// ToPion converts SDPBfcp to a pion MediaDescription.
func (b *SDPBfcp) ToPion() (sdp.MediaDescription, error) {
	attrs := []sdp.Attribute{
		{Key: "setup", Value: string(b.Setup)},
		{Key: "connection", Value: string(b.Connection)},
		{Key: "floorctrl", Value: string(b.FloorCtrl)},
		{Key: "confid", Value: fmt.Sprintf("%d", b.ConfID)},
		{Key: "userid", Value: fmt.Sprintf("%d", b.UserID)},
	}

	floorValue := fmt.Sprintf("%d", b.FloorID)
	if b.MStreamID > 0 {
		floorValue = fmt.Sprintf("%d mstrm:%d", b.FloorID, b.MStreamID)
	}
	attrs = append(attrs, sdp.Attribute{Key: "floorid", Value: floorValue})

	protos := []string{"TCP", "BFCP"}
	if b.Proto == BfcpProtoTCPTLS {
		protos = []string{"TCP", "TLS", "BFCP"}
	}

	port := int(b.Port)
	if b.Disabled {
		port = 0
	}

	md := sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   "application",
			Port:    sdp.RangedPort{Value: port},
			Protos:  protos,
			Formats: []string{"*"},
		},
		Attributes: attrs,
	}

	return md, nil
}

// Clone creates a deep copy of SDPBfcp.
func (b *SDPBfcp) Clone() *SDPBfcp {
	if b == nil {
		return nil
	}
	return &SDPBfcp{
		Disabled:       b.Disabled,
		Port:           b.Port,
		Proto:          b.Proto,
		Setup:          b.Setup,
		Connection:     b.Connection,
		FloorCtrl:      b.FloorCtrl,
		ConfID:         b.ConfID,
		UserID:         b.UserID,
		FloorID:        b.FloorID,
		MStreamID:      b.MStreamID,
		ConnectionAddr: b.ConnectionAddr,
	}
}

// Builder returns a new SDPBfcpBuilder initialized with a clone of this SDPBfcp.
func (b *SDPBfcp) Builder() *SDPBfcpBuilder {
	return &SDPBfcpBuilder{b: b.Clone()}
}

// SDPBfcpBuilder provides a fluent interface for constructing SDPBfcp.
type SDPBfcpBuilder struct {
	errs []error
	b    *SDPBfcp
}

// NewSDPBfcpBuilder creates a new builder with default values.
func NewSDPBfcpBuilder() *SDPBfcpBuilder {
	return &SDPBfcpBuilder{b: &SDPBfcp{
		Proto:      BfcpProtoTCP,
		Connection: BfcpConnectionNew,
	}}
}

// Build returns the constructed SDPBfcp or an error if validation fails.
func (bb *SDPBfcpBuilder) Build() (*SDPBfcp, error) {
	if len(bb.errs) > 0 {
		return nil, fmt.Errorf("failed to build SDPBfcp: %w", errors.Join(bb.errs...))
	}
	return bb.b, nil
}

// SetPort sets the media port.
func (bb *SDPBfcpBuilder) SetPort(port uint16) *SDPBfcpBuilder {
	bb.b.Port = port
	bb.b.Disabled = port == 0
	return bb
}

// SetProto sets the protocol (TCP/BFCP or TCP/TLS/BFCP).
func (bb *SDPBfcpBuilder) SetProto(proto BfcpProto) *SDPBfcpBuilder {
	bb.b.Proto = proto
	return bb
}

// SetSetup sets the connection setup role.
func (bb *SDPBfcpBuilder) SetSetup(setup BfcpSetup) *SDPBfcpBuilder {
	bb.b.Setup = setup
	return bb
}

// SetConnection sets the connection reuse policy.
func (bb *SDPBfcpBuilder) SetConnection(conn BfcpConnection) *SDPBfcpBuilder {
	bb.b.Connection = conn
	return bb
}

// SetFloorCtrl sets the floor control role.
func (bb *SDPBfcpBuilder) SetFloorCtrl(fc BfcpFloorCtrl) *SDPBfcpBuilder {
	bb.b.FloorCtrl = fc
	return bb
}

// SetConfID sets the conference ID.
func (bb *SDPBfcpBuilder) SetConfID(id uint32) *SDPBfcpBuilder {
	bb.b.ConfID = id
	return bb
}

// SetUserID sets the user ID.
func (bb *SDPBfcpBuilder) SetUserID(id uint32) *SDPBfcpBuilder {
	bb.b.UserID = id
	return bb
}

// SetFloorID sets the floor ID.
func (bb *SDPBfcpBuilder) SetFloorID(id uint16) *SDPBfcpBuilder {
	bb.b.FloorID = id
	return bb
}

// SetMStreamID sets the media stream association ID.
func (bb *SDPBfcpBuilder) SetMStreamID(id uint16) *SDPBfcpBuilder {
	bb.b.MStreamID = id
	return bb
}

// SetDisabled sets whether the BFCP media is disabled (port 0).
func (bb *SDPBfcpBuilder) SetDisabled(disabled bool) *SDPBfcpBuilder {
	bb.b.Disabled = disabled
	if disabled {
		bb.b.Port = 0
	}
	return bb
}

// SDPBfcpAnswerConfig holds configuration for generating a BFCP answer.
type SDPBfcpAnswerConfig struct {
	Port           uint16     // Local port (0 = use offer port)
	ConnectionAddr netip.Addr // Media-level connection address for c= line
	ConfID         uint32     // Conference ID (0 = use offer)
	UserID         uint32     // User ID (0 = use offer)
	FloorID        uint16     // Floor ID (0 = use offer)
	MStreamID      uint16     // Media stream ID (0 = use offer)
}

// Answer creates a BFCP answer from this offer with reversed roles.
func (b *SDPBfcp) Answer(config *SDPBfcpAnswerConfig) *SDPBfcp {
	if config == nil {
		config = &SDPBfcpAnswerConfig{}
	}

	// Use offer values as defaults if config doesn't specify
	port := config.Port
	if port == 0 {
		port = b.Port
	}

	confID := config.ConfID
	if confID == 0 {
		confID = b.ConfID
	}

	userID := config.UserID
	if userID == 0 {
		userID = b.UserID
	}

	floorID := config.FloorID
	if floorID == 0 {
		floorID = b.FloorID
	}

	mstrmID := config.MStreamID
	if mstrmID == 0 {
		mstrmID = b.MStreamID
	}

	return &SDPBfcp{
		Disabled:       port == 0,
		Port:           port,
		Proto:          b.Proto,
		Setup:          b.Setup.Reverse(),
		Connection:     BfcpConnectionNew,
		FloorCtrl:      b.FloorCtrl.Reverse(),
		ConfID:         confID,
		UserID:         userID,
		FloorID:        floorID,
		MStreamID:      mstrmID,
		ConnectionAddr: config.ConnectionAddr,
	}
}

// Marshal converts the SDPBfcp to SDP m-line string format.
func (b *SDPBfcp) Marshal() (string, error) {
	md, err := b.ToPion()
	if err != nil {
		return "", err
	}

	// Marshal MediaDescription manually
	result := fmt.Sprintf("m=%s %d %s %s\r\n",
		md.MediaName.Media,
		md.MediaName.Port.Value,
		strings.Join(md.MediaName.Protos, "/"),
		strings.Join(md.MediaName.Formats, " "),
	)

	// Add media-level c= line if ConnectionAddr is set
	if b.ConnectionAddr.IsValid() {
		result += fmt.Sprintf("c=IN IP4 %s\r\n", b.ConnectionAddr.String())
	}

	for _, attr := range md.Attributes {
		if attr.Value != "" {
			result += fmt.Sprintf("a=%s:%s\r\n", attr.Key, attr.Value)
		} else {
			result += fmt.Sprintf("a=%s\r\n", attr.Key)
		}
	}

	return result, nil
}
