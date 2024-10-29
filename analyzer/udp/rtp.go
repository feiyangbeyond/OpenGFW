package udp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/pion/rtp"
)

const (
	rtpInvalidCountThreshold = 4
)

var (
	_ analyzer.UDPAnalyzer = (*RTPAnalyzer)(nil)
	_ analyzer.UDPStream   = (*rtpStream)(nil)
)

type RTPAnalyzer struct{}

func (a *RTPAnalyzer) Name() string {
	return "rtp"
}

func (a *RTPAnalyzer) Limit() int {
	return 0
}

func (a *RTPAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &rtpStream{logger: logger}
}

type rtpStream struct {
	logger       analyzer.Logger
	invalidCount int
}

func (s *rtpStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	p := rtp.Packet{}
	if err := p.Unmarshal(data); err != nil {
		s.invalidCount++
		return nil, s.invalidCount >= rtpInvalidCountThreshold
	}

	s.logger.Debugf("rtp packet detected: %s", p.String())

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M: analyzer.PropMap{
			"payload_type": p.Header.PayloadType, // PayloadType Definitions: https://www.rfc-editor.org/rfc/rfc3551.html#section-6
			"yes":          true,
		},
	}, true
}

func (s *rtpStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}
