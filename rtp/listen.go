// Copyright 2023 LiveKit, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rtp

import (
	"errors"
	"math/rand"
	"net"
	"net/netip"
)

var ErrListenFailed = errors.New("failed to listen on udp port")

// ListenUDPPortPair allocates a pair of consecutive UDP ports for RTP/RTCP according to RFC 3550.
// RTP is allocated on an even port, RTCP on the next odd port (RTP+1).
// Returns (rtpConn, rtcpConn, error).
func ListenUDPPortPair(portMin, portMax int, ip netip.Addr) (*net.UDPConn, *net.UDPConn, error) {
	if portMin == 0 && portMax == 0 {
		portMin = 1024
		portMax = 0xFFFF
	}

	i := portMin
	if i == 0 {
		i = 1
	}
	// Ensure we start on an even port
	if i%2 != 0 {
		i++
	}

	j := portMax
	if j == 0 {
		j = 0xFFFF
	}

	if i > j {
		return nil, nil, ErrListenFailed
	}

	// Start from a random even port
	portRange := (j - i) / 2
	if portRange <= 0 {
		portRange = 1
	}
	portStart := (rand.Intn(portRange) * 2) + i
	if portStart%2 != 0 {
		portStart++
	}

	portCurrent := portStart

	for {
		// Try to allocate RTP on even port
		rtpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip.AsSlice(), Port: portCurrent})
		if err == nil {
			// Try to allocate RTCP on next port (RTP+1)
			rtcpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip.AsSlice(), Port: portCurrent + 1})
			if err == nil {
				return rtpConn, rtcpConn, nil
			}
			// Failed to allocate RTCP, close RTP and try next pair
			rtpConn.Close()
		}

		portCurrent += 2 // Move to next even port
		if portCurrent > j {
			portCurrent = i
			if portCurrent%2 != 0 {
				portCurrent++
			}
		}
		if portCurrent == portStart {
			break
		}
	}
	return nil, nil, ErrListenFailed
}

func ListenUDPPortRange(portMin, portMax int, ip netip.Addr) (*net.UDPConn, error) {
	if portMin == 0 && portMax == 0 {
		return net.ListenUDP("udp", &net.UDPAddr{
			IP:   ip.AsSlice(),
			Port: 0,
		})
	}

	i := portMin
	if i == 0 {
		i = 1
	}

	j := portMax
	if j == 0 {
		j = 0xFFFF
	}

	if i > j {
		return nil, ErrListenFailed
	}

	portStart := rand.Intn(portMax-portMin+1) + portMin
	portCurrent := portStart

	for {
		c, e := net.ListenUDP("udp", &net.UDPAddr{IP: ip.AsSlice(), Port: portCurrent})
		if e == nil {
			return c, nil
		}

		portCurrent++
		if portCurrent > j {
			portCurrent = i
		}
		if portCurrent == portStart {
			break
		}
	}
	return nil, ErrListenFailed
}
