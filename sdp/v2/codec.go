package v2

import (
	media "github.com/livekit/media-sdk"
	v1 "github.com/livekit/media-sdk/sdp"
	"github.com/pion/sdp/v3"
)

func (c *Codec) Clone() *Codec {
	return &Codec{
		PayloadType: c.PayloadType,
		Name:        c.Name,
		Codec:       c.Codec,
		ClockRate:   c.ClockRate,
		FMTP: func() map[string]string {
			if c.FMTP == nil {
				return nil
			}
			fmtp := make(map[string]string, len(c.FMTP))
			for k, v := range c.FMTP {
				fmtp[k] = v
			}
			return fmtp
		}(),
		RTCPFB: func() []sdp.Attribute {
			if c.RTCPFB == nil {
				return nil
			}
			rtcpfb := make([]sdp.Attribute, len(c.RTCPFB))
			for i, v := range c.RTCPFB {
				rtcpfb[i].Key = v.Key
				rtcpfb[i].Value = v.Value
			}
			return rtcpfb
		}(),
	}
}

func (c *Codec) FmtpParts() []string {
	if len(c.FMTP) == 0 {
		return nil
	}
	parts := make([]string, 0, len(c.FMTP))
	for k, v := range c.FMTP {
		if v == "" {
			parts = append(parts, k)
		} else {
			parts = append(parts, k+"="+v)
		}
	}
	return parts
}

func (c *Codec) Builder() *CodecBuilder {
	return &CodecBuilder{c: c.Clone()}
}

type CodecBuilder struct {
	c *Codec
}

func (b *CodecBuilder) Load(c *Codec) Builder[*Codec] {
	b.c = c
	return b
}

func (b *CodecBuilder) Build() (*Codec, error) {
	if b.c.Codec == nil {
		return nil, v1.ErrNoCommonMedia
	}

	info := b.c.Codec.Info()

	if b.c.PayloadType == 0 {
		b.c.PayloadType = info.RTPDefType
	}
	if b.c.Name == "" {
		b.c.Name = info.SDPName
	}
	if b.c.ClockRate == 0 {
		b.c.ClockRate = uint32(info.RTPClockRate)
	}
	return b.c, nil
}

func (b *CodecBuilder) SetPayloadType(pt uint8) *CodecBuilder {
	b.c.PayloadType = pt
	return b
}

func (b *CodecBuilder) SetCodec(codec media.Codec) *CodecBuilder {
	b.c.Codec = codec
	return b
}

func (b *CodecBuilder) SetFMTP(fmtp map[string]string) *CodecBuilder {
	b.c.FMTP = fmtp
	return b
}

func (b *CodecBuilder) SetRTCPFB(rtcpfb []sdp.Attribute) *CodecBuilder {
	b.c.RTCPFB = rtcpfb
	return b
}
