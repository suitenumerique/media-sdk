package bfcp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pion/sdp/v3"
)

// ParseBFCPMedia extracts BFCP attributes from a pion MediaDescription.
// Returns an error if the media description is not a valid BFCP media.
func ParseBFCPMedia(md *sdp.MediaDescription) (*MediaInfo, error) {
	if md == nil {
		return nil, fmt.Errorf("media description is nil")
	}

	// Validate media type is application
	if md.MediaName.Media != "application" {
		return nil, fmt.Errorf("expected application media, got %s", md.MediaName.Media)
	}

	// Validate protocol contains BFCP
	proto := strings.Join(md.MediaName.Protos, "/")
	if !strings.Contains(strings.ToUpper(proto), "BFCP") {
		return nil, fmt.Errorf("expected BFCP protocol, got %s", proto)
	}

	info := &MediaInfo{
		Port:  uint16(md.MediaName.Port.Value),
		Proto: proto,
	}

	// Parse attributes
	for _, attr := range md.Attributes {
		switch attr.Key {
		case "setup":
			info.Setup = Setup(attr.Value)
		case "connection":
			info.Connection = Connection(attr.Value)
		case "floorctrl":
			info.FloorCtrl = FloorCtrl(attr.Value)
		case "confid":
			if v, err := strconv.ParseUint(attr.Value, 10, 32); err == nil {
				info.ConfID = uint32(v)
			}
		case "userid":
			if v, err := strconv.ParseUint(attr.Value, 10, 32); err == nil {
				info.UserID = uint32(v)
			}
		case "floorid":
			parseFloorID(attr.Value, info)
		}
	}

	return info, nil
}

// parseFloorID parses the floorid attribute value.
// Format: "N" or "N mstrm:M"
func parseFloorID(value string, info *MediaInfo) {
	parts := strings.Fields(value)
	if len(parts) >= 1 {
		if v, err := strconv.ParseUint(parts[0], 10, 16); err == nil {
			info.FloorID = uint16(v)
		}
	}
	if len(parts) >= 2 && strings.HasPrefix(parts[1], "mstrm:") {
		if v, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "mstrm:"), 10, 16); err == nil {
			info.MStreamID = uint16(v)
		}
	}
}

// ParseBFCPFromSDP extracts all BFCP media sections from raw SDP bytes.
// Returns a slice of MediaInfo for each BFCP m-line found, or nil if none.
func ParseBFCPFromSDP(sdpData []byte) ([]*MediaInfo, error) {
	var psdp sdp.SessionDescription
	if err := psdp.Unmarshal(sdpData); err != nil {
		return nil, fmt.Errorf("failed to parse SDP: %w", err)
	}

	var results []*MediaInfo
	for _, md := range psdp.MediaDescriptions {
		if md.MediaName.Media != "application" {
			continue
		}
		info, err := ParseBFCPMedia(md)
		if err != nil {
			// Not a BFCP media, skip
			continue
		}
		results = append(results, info)
	}

	return results, nil
}
