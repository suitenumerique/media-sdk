package bfcp

import (
	"testing"

	"github.com/pion/sdp/v3"
	"github.com/stretchr/testify/require"
)

func TestParseBFCPMedia(t *testing.T) {
	// Test case from user's example:
	// m=application 10006 TCP/BFCP *
	// a=setup:active
	// a=connection:new
	// a=floorctrl:c-only
	// a=confid:1
	// a=userid:100
	// a=floorid:2 mstrm:2
	md := &sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   "application",
			Port:    sdp.RangedPort{Value: 10006},
			Protos:  []string{"TCP", "BFCP"},
			Formats: []string{"*"},
		},
		Attributes: []sdp.Attribute{
			{Key: "setup", Value: "active"},
			{Key: "connection", Value: "new"},
			{Key: "floorctrl", Value: "c-only"},
			{Key: "confid", Value: "1"},
			{Key: "userid", Value: "100"},
			{Key: "floorid", Value: "2 mstrm:2"},
		},
	}

	info, err := ParseBFCPMedia(md)
	require.NoError(t, err)
	require.Equal(t, uint16(10006), info.Port)
	require.Equal(t, "TCP/BFCP", info.Proto)
	require.Equal(t, SetupActive, info.Setup)
	require.Equal(t, ConnectionNew, info.Connection)
	require.Equal(t, FloorCtrlClient, info.FloorCtrl)
	require.Equal(t, uint32(1), info.ConfID)
	require.Equal(t, uint32(100), info.UserID)
	require.Equal(t, uint16(2), info.FloorID)
	require.Equal(t, uint16(2), info.MStreamID)
}

func TestParseBFCPMedia_TLS(t *testing.T) {
	md := &sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   "application",
			Port:    sdp.RangedPort{Value: 10006},
			Protos:  []string{"TCP", "TLS", "BFCP"},
			Formats: []string{"*"},
		},
		Attributes: []sdp.Attribute{
			{Key: "setup", Value: "actpass"},
			{Key: "connection", Value: "new"},
			{Key: "floorctrl", Value: "c-s"},
			{Key: "confid", Value: "42"},
			{Key: "userid", Value: "200"},
			{Key: "floorid", Value: "5"},
		},
	}

	info, err := ParseBFCPMedia(md)
	require.NoError(t, err)
	require.Equal(t, "TCP/TLS/BFCP", info.Proto)
	require.Equal(t, SetupActpass, info.Setup)
	require.Equal(t, FloorCtrlBoth, info.FloorCtrl)
	require.Equal(t, uint32(42), info.ConfID)
	require.Equal(t, uint32(200), info.UserID)
	require.Equal(t, uint16(5), info.FloorID)
	require.Equal(t, uint16(0), info.MStreamID) // No mstrm
}

func TestParseBFCPMedia_InvalidMedia(t *testing.T) {
	// Not application media
	md := &sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   "audio",
			Port:    sdp.RangedPort{Value: 10006},
			Protos:  []string{"RTP", "AVP"},
			Formats: []string{"0"},
		},
	}

	_, err := ParseBFCPMedia(md)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected application media")
}

func TestParseBFCPMedia_InvalidProtocol(t *testing.T) {
	md := &sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   "application",
			Port:    sdp.RangedPort{Value: 10006},
			Protos:  []string{"UDP", "DTLS"},
			Formats: []string{"*"},
		},
	}

	_, err := ParseBFCPMedia(md)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected BFCP protocol")
}

func TestParseBFCPMedia_Nil(t *testing.T) {
	_, err := ParseBFCPMedia(nil)
	require.Error(t, err)
}

func TestCreateBFCPAnswer(t *testing.T) {
	offer := &MediaInfo{
		Port:       10006,
		Proto:      "TCP/BFCP",
		Setup:      SetupActive,
		Connection: ConnectionNew,
		FloorCtrl:  FloorCtrlClient,
		ConfID:     1,
		UserID:     100,
		FloorID:    2,
		MStreamID:  2,
	}

	config := &AnswerConfig{
		Port: 10007,
	}

	answer, err := CreateBFCPAnswer(offer, config)
	require.NoError(t, err)
	require.Equal(t, "application", answer.MediaName.Media)
	require.Equal(t, 10007, answer.MediaName.Port.Value)
	require.Equal(t, []string{"TCP", "BFCP"}, answer.MediaName.Protos)
	require.Equal(t, []string{"*"}, answer.MediaName.Formats)

	// Verify passive setup in answer (reversed from active)
	setup, ok := answer.Attribute("setup")
	require.True(t, ok)
	require.Equal(t, "passive", setup)

	// Verify server floor control in answer (reversed from c-only)
	floorctrl, ok := answer.Attribute("floorctrl")
	require.True(t, ok)
	require.Equal(t, "s-only", floorctrl)

	// Verify connection is new
	connection, ok := answer.Attribute("connection")
	require.True(t, ok)
	require.Equal(t, "new", connection)

	// Verify IDs are preserved
	confid, ok := answer.Attribute("confid")
	require.True(t, ok)
	require.Equal(t, "1", confid)

	userid, ok := answer.Attribute("userid")
	require.True(t, ok)
	require.Equal(t, "100", userid)

	floorid, ok := answer.Attribute("floorid")
	require.True(t, ok)
	require.Equal(t, "2 mstrm:2", floorid)
}

func TestCreateBFCPAnswer_WithTLS(t *testing.T) {
	offer := &MediaInfo{
		Port:      10006,
		Proto:     "TCP/TLS/BFCP",
		Setup:     SetupActpass,
		FloorCtrl: FloorCtrlBoth,
		ConfID:    42,
		UserID:    200,
		FloorID:   5,
	}

	answer, err := CreateBFCPAnswer(offer, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"TCP", "TLS", "BFCP"}, answer.MediaName.Protos)

	// actpass should reverse to passive
	setup, _ := answer.Attribute("setup")
	require.Equal(t, "passive", setup)

	// c-s should stay c-s
	floorctrl, _ := answer.Attribute("floorctrl")
	require.Equal(t, "c-s", floorctrl)
}

func TestCreateBFCPAnswer_NilOffer(t *testing.T) {
	_, err := CreateBFCPAnswer(nil, nil)
	require.Error(t, err)
}

func TestSetupReverse(t *testing.T) {
	require.Equal(t, SetupPassive, SetupActive.Reverse())
	require.Equal(t, SetupActive, SetupPassive.Reverse())
	require.Equal(t, SetupPassive, SetupActpass.Reverse())
}

func TestFloorCtrlReverse(t *testing.T) {
	require.Equal(t, FloorCtrlServer, FloorCtrlClient.Reverse())
	require.Equal(t, FloorCtrlClient, FloorCtrlServer.Reverse())
	require.Equal(t, FloorCtrlBoth, FloorCtrlBoth.Reverse())
}

func TestParseBFCPFromSDP(t *testing.T) {
	// Full SDP with audio, video, and BFCP
	sdpData := []byte(`v=0
o=- 123456 123456 IN IP4 192.168.1.100
s=Test Session
c=IN IP4 192.168.1.100
t=0 0
m=audio 5000 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
m=video 5002 RTP/AVP 96
a=rtpmap:96 H264/90000
a=sendrecv
m=application 10006 TCP/BFCP *
a=setup:active
a=connection:new
a=floorctrl:c-only
a=confid:1
a=userid:100
a=floorid:2 mstrm:2
`)

	results, err := ParseBFCPFromSDP(sdpData)
	require.NoError(t, err)
	require.Len(t, results, 1)

	info := results[0]
	require.Equal(t, uint16(10006), info.Port)
	require.Equal(t, "TCP/BFCP", info.Proto)
	require.Equal(t, SetupActive, info.Setup)
	require.Equal(t, ConnectionNew, info.Connection)
	require.Equal(t, FloorCtrlClient, info.FloorCtrl)
	require.Equal(t, uint32(1), info.ConfID)
	require.Equal(t, uint32(100), info.UserID)
	require.Equal(t, uint16(2), info.FloorID)
	require.Equal(t, uint16(2), info.MStreamID)
}

func TestParseBFCPFromSDP_NoBFCP(t *testing.T) {
	// SDP without BFCP
	sdpData := []byte(`v=0
o=- 123456 123456 IN IP4 192.168.1.100
s=Test Session
c=IN IP4 192.168.1.100
t=0 0
m=audio 5000 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
`)

	results, err := ParseBFCPFromSDP(sdpData)
	require.NoError(t, err)
	require.Len(t, results, 0)
}
