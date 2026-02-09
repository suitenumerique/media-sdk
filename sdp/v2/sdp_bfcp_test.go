package v2

import (
	"net/netip"
	"testing"

	"github.com/pion/sdp/v3"
	"github.com/stretchr/testify/require"
)

// TestSDPBfcp_FromPion_WithConnectionInfo tests that FromPion correctly parses
// a media-level c= line into ConnectionAddr. This is critical for Aver devices
// which include c=IN IP4 <addr> in their BFCP m-line section.
func TestSDPBfcp_FromPion_WithConnectionInfo(t *testing.T) {
	md := sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   "application",
			Port:    sdp.RangedPort{Value: 50532},
			Protos:  []string{"TCP", "BFCP"},
			Formats: []string{"*"},
		},
		ConnectionInformation: &sdp.ConnectionInformation{
			NetworkType: "IN",
			AddressType: "IP4",
			Address:     &sdp.Address{Address: "148.253.73.224"},
		},
		Attributes: []sdp.Attribute{
			{Key: "setup", Value: "passive"},
			{Key: "connection", Value: "new"},
			{Key: "floorctrl", Value: "c-s"},
			{Key: "confid", Value: "1"},
			{Key: "userid", Value: "1"},
			{Key: "floorid", Value: "1 m-stream:3"},
		},
	}

	var b SDPBfcp
	err := b.FromPion(md)
	require.NoError(t, err)
	require.Equal(t, uint16(50532), b.Port)
	require.Equal(t, BfcpSetupPassive, b.Setup)
	require.Equal(t, uint16(1), b.FloorID)
	require.Equal(t, uint16(3), b.MStreamID)
	require.True(t, b.ConnectionAddr.IsValid())
	require.Equal(t, netip.MustParseAddr("148.253.73.224"), b.ConnectionAddr)
}

// TestSDPBfcp_FromPion_WithoutConnectionInfo tests that FromPion leaves
// ConnectionAddr empty when no media-level c= line is present. This is the
// normal case for Poly and Cisco devices where BFCP uses the session-level address.
func TestSDPBfcp_FromPion_WithoutConnectionInfo(t *testing.T) {
	md := sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   "application",
			Port:    sdp.RangedPort{Value: 10006},
			Protos:  []string{"TCP", "BFCP"},
			Formats: []string{"*"},
		},
		Attributes: []sdp.Attribute{
			{Key: "setup", Value: "actpass"},
			{Key: "connection", Value: "new"},
			{Key: "floorctrl", Value: "c-s"},
			{Key: "confid", Value: "1"},
			{Key: "userid", Value: "100"},
			{Key: "floorid", Value: "2 mstrm:2"},
		},
	}

	var b SDPBfcp
	err := b.FromPion(md)
	require.NoError(t, err)
	require.Equal(t, uint16(10006), b.Port)
	require.Equal(t, BfcpSetupActpass, b.Setup)
	require.Equal(t, uint16(2), b.FloorID)
	require.Equal(t, uint16(2), b.MStreamID)
	require.False(t, b.ConnectionAddr.IsValid())
}

// TestSDPBfcp_FromPion_MStreamHyphenated tests that FromPion correctly parses
// the RFC 4583 hyphenated "m-stream:" format used by Aver devices.
func TestSDPBfcp_FromPion_MStreamHyphenated(t *testing.T) {
	md := sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   "application",
			Port:    sdp.RangedPort{Value: 50532},
			Protos:  []string{"TCP", "BFCP"},
			Formats: []string{"*"},
		},
		Attributes: []sdp.Attribute{
			{Key: "setup", Value: "passive"},
			{Key: "connection", Value: "new"},
			{Key: "floorctrl", Value: "c-s"},
			{Key: "confid", Value: "1"},
			{Key: "userid", Value: "1"},
			{Key: "floorid", Value: "1 m-stream:3"},
		},
	}

	var b SDPBfcp
	err := b.FromPion(md)
	require.NoError(t, err)
	require.Equal(t, uint16(1), b.FloorID)
	require.Equal(t, uint16(3), b.MStreamID)
}

// TestSDPBfcp_FromPion_MStreamCompact is a regression test ensuring the compact
// "mstrm:" format (used by Poly and Cisco) still works after adding m-stream: support.
func TestSDPBfcp_FromPion_MStreamCompact(t *testing.T) {
	md := sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   "application",
			Port:    sdp.RangedPort{Value: 10006},
			Protos:  []string{"TCP", "BFCP"},
			Formats: []string{"*"},
		},
		Attributes: []sdp.Attribute{
			{Key: "setup", Value: "actpass"},
			{Key: "connection", Value: "new"},
			{Key: "floorctrl", Value: "c-s"},
			{Key: "confid", Value: "1"},
			{Key: "userid", Value: "100"},
			{Key: "floorid", Value: "2 mstrm:2"},
		},
	}

	var b SDPBfcp
	err := b.FromPion(md)
	require.NoError(t, err)
	require.Equal(t, uint16(2), b.FloorID)
	require.Equal(t, uint16(2), b.MStreamID)
}
