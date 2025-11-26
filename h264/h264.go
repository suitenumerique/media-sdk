package h264

import "github.com/livekit/media-sdk"

const SDPName = "H264/90000"

func init() {
	media.RegisterCodec(media.NewCodec(media.CodecInfo{
		SDPName:      SDPName,
		SampleRate:   90000,
		RTPClockRate: 90000,
		RTPDefType:   97,
		RTPIsStatic:  false,
		Priority:     100,
		FileExt:      "h264",
	}))
}
