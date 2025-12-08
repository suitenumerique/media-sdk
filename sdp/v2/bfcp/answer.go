package bfcp

import (
	"fmt"

	"github.com/pion/sdp/v3"
)

// CreateBFCPAnswer generates a BFCP media answer from an offer.
// The server responds with passive setup and reversed floor control role.
func CreateBFCPAnswer(offer *MediaInfo, config *AnswerConfig) (*sdp.MediaDescription, error) {
	if offer == nil {
		return nil, fmt.Errorf("offer cannot be nil")
	}
	if config == nil {
		config = &AnswerConfig{}
	}

	// Use offer values as defaults if config doesn't specify
	port := config.Port
	if port == 0 {
		port = offer.Port
	}

	confID := config.ConfID
	if confID == 0 {
		confID = offer.ConfID
	}

	userID := config.UserID
	if userID == 0 {
		userID = offer.UserID
	}

	floorID := config.FloorID
	if floorID == 0 {
		floorID = offer.FloorID
	}

	mstrmID := config.MStreamID
	if mstrmID == 0 {
		mstrmID = offer.MStreamID
	}

	// Build attributes
	attrs := []sdp.Attribute{
		{Key: "setup", Value: string(offer.Setup.Reverse())},
		{Key: "connection", Value: string(ConnectionNew)},
		{Key: "floorctrl", Value: string(offer.FloorCtrl.Reverse())},
		{Key: "confid", Value: fmt.Sprintf("%d", confID)},
		{Key: "userid", Value: fmt.Sprintf("%d", userID)},
	}

	// Add floorid with optional mstrm association
	floorValue := fmt.Sprintf("%d", floorID)
	if mstrmID > 0 {
		floorValue = fmt.Sprintf("%d mstrm:%d", floorID, mstrmID)
	}
	attrs = append(attrs, sdp.Attribute{Key: "floorid", Value: floorValue})

	// Parse protocol parts from offer
	protos := []string{"TCP", "BFCP"}
	if offer.Proto != "" {
		// Handle TCP/TLS/BFCP case
		if offer.Proto == "TCP/TLS/BFCP" {
			protos = []string{"TCP", "TLS", "BFCP"}
		}
	}

	md := &sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   "application",
			Port:    sdp.RangedPort{Value: int(port)},
			Protos:  protos,
			Formats: []string{"*"},
		},
		Attributes: attrs,
	}

	return md, nil
}

// MarshalBFCPAnswer creates and marshals a BFCP answer to SDP string.
// Returns the m= line and attributes ready to append to an SDP answer.
func MarshalBFCPAnswer(offer *MediaInfo, config *AnswerConfig) (string, error) {
	md, err := CreateBFCPAnswer(offer, config)
	if err != nil {
		return "", err
	}

	// Marshal MediaDescription manually since pion/sdp doesn't expose Marshal for MediaDescription
	result := fmt.Sprintf("m=%s %d %s %s\r\n",
		md.MediaName.Media,
		md.MediaName.Port.Value,
		joinProtos(md.MediaName.Protos),
		joinFormats(md.MediaName.Formats),
	)

	for _, attr := range md.Attributes {
		if attr.Value != "" {
			result += fmt.Sprintf("a=%s:%s\r\n", attr.Key, attr.Value)
		} else {
			result += fmt.Sprintf("a=%s\r\n", attr.Key)
		}
	}

	return result, nil
}

func joinProtos(protos []string) string {
	result := ""
	for i, p := range protos {
		if i > 0 {
			result += "/"
		}
		result += p
	}
	return result
}

func joinFormats(formats []string) string {
	result := ""
	for i, f := range formats {
		if i > 0 {
			result += " "
		}
		result += f
	}
	return result
}
