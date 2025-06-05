package extproc

import "google.golang.org/protobuf/types/known/structpb"

type HeaderValue struct {
	Values []string
}

type HttpHeaders struct {
	Headers     map[string]*HeaderValue
	EndOfStream bool
}

type RequestHeaders struct {
	Headers   *HttpHeaders
	Method    string
	Path      string
	Authority string
	Scheme    string
}

type ResponseHeaders struct {
	Headers    *HttpHeaders
	StatusCode int32
}

type HttpBodyChunk struct {
	Chunk       []byte
	EndOfStream bool
}

type RequestBodyChunk struct {
	BodyChunk *HttpBodyChunk
}

type ResponseBodyChunk struct {
	BodyChunk *HttpBodyChunk
}

type StreamTrailer struct {
	Trailers map[string]*HeaderValue
}

type ProcessingRequestChunk struct {
	RequestId       string
	RouteId         string
	PluginConfig    *structpb.Struct
	RequestMetadata map[string]string
	PhaseData       isProcessingRequestChunk_PhaseData
}

type isProcessingRequestChunk_PhaseData interface{ isProcessingRequestChunk_PhaseData() }

type ProcessingRequestChunk_RequestHeaders struct{ RequestHeaders *RequestHeaders }

func (*ProcessingRequestChunk_RequestHeaders) isProcessingRequestChunk_PhaseData() {}

type ProcessingRequestChunk_RequestBodyChunk struct{ RequestBodyChunk *RequestBodyChunk }

func (*ProcessingRequestChunk_RequestBodyChunk) isProcessingRequestChunk_PhaseData() {}

type ProcessingRequestChunk_ResponseHeaders struct{ ResponseHeaders *ResponseHeaders }

func (*ProcessingRequestChunk_ResponseHeaders) isProcessingRequestChunk_PhaseData() {}

type ProcessingRequestChunk_ResponseBodyChunk struct{ ResponseBodyChunk *ResponseBodyChunk }

func (*ProcessingRequestChunk_ResponseBodyChunk) isProcessingRequestChunk_PhaseData() {}

type ProcessingRequestChunk_StreamTrailer struct{ StreamTrailer *StreamTrailer }

func (*ProcessingRequestChunk_StreamTrailer) isProcessingRequestChunk_PhaseData() {}

func (m *ProcessingRequestChunk) GetRequestHeaders() *RequestHeaders {
	if x, ok := m.PhaseData.(*ProcessingRequestChunk_RequestHeaders); ok {
		return x.RequestHeaders
	}
	return nil
}
func (m *ProcessingRequestChunk) GetRequestBodyChunk() *RequestBodyChunk {
	if x, ok := m.PhaseData.(*ProcessingRequestChunk_RequestBodyChunk); ok {
		return x.RequestBodyChunk
	}
	return nil
}
func (m *ProcessingRequestChunk) GetStreamTrailer() *StreamTrailer {
	if x, ok := m.PhaseData.(*ProcessingRequestChunk_StreamTrailer); ok {
		return x.StreamTrailer
	}
	return nil
}
func (m *ProcessingRequestChunk) GetPluginConfig() *structpb.Struct {
	if m != nil {
		return m.PluginConfig
	}
	return nil
}

type ProcessingResponseChunk struct {
	Action isProcessingResponseChunk_Action
}

type isProcessingResponseChunk_Action interface{ isProcessingResponseChunk_Action() }

type ProcessingResponseChunk_CommonResponse struct{ CommonResponse *CommonResponse }

func (*ProcessingResponseChunk_CommonResponse) isProcessingResponseChunk_Action() {}

type ProcessingResponseChunk_HeaderMutation struct{ HeaderMutation *HeaderMutation }

func (*ProcessingResponseChunk_HeaderMutation) isProcessingResponseChunk_Action() {}

type ProcessingResponseChunk_BodyMutation struct{ BodyMutation *BodyMutation }

func (*ProcessingResponseChunk_BodyMutation) isProcessingResponseChunk_Action() {}

type ProcessingResponseChunk_ImmediateResponse struct{ ImmediateResponse *ImmediateResponse }

func (*ProcessingResponseChunk_ImmediateResponse) isProcessingResponseChunk_Action() {}

func (m *ProcessingResponseChunk) GetCommonResponse() *CommonResponse {
	if x, ok := m.Action.(*ProcessingResponseChunk_CommonResponse); ok {
		return x.CommonResponse
	}
	return nil
}
func (m *ProcessingResponseChunk) GetHeaderMutation() *HeaderMutation {
	if x, ok := m.Action.(*ProcessingResponseChunk_HeaderMutation); ok {
		return x.HeaderMutation
	}
	return nil
}
func (m *ProcessingResponseChunk) GetBodyMutation() *BodyMutation {
	if x, ok := m.Action.(*ProcessingResponseChunk_BodyMutation); ok {
		return x.BodyMutation
	}
	return nil
}
func (m *ProcessingResponseChunk) GetImmediateResponse() *ImmediateResponse {
	if x, ok := m.Action.(*ProcessingResponseChunk_ImmediateResponse); ok {
		return x.ImmediateResponse
	}
	return nil
}

type HeaderPair struct {
	Key   string
	Value string
}

type HeaderMutation struct {
	SetHeaders    []*HeaderPair
	RemoveHeaders []string
}

type BodyMutation struct {
	Chunk       []byte
	EndOfStream bool
}

func (b *BodyMutation) GetChunk() []byte {
	if b != nil {
		return b.Chunk
	}
	return nil
}

func (b *BodyMutation) GetEndOfStream() bool {
	if b != nil {
		return b.EndOfStream
	}
	return false
}

type ImmediateResponse struct {
	StatusCode int32
	Headers    *HttpHeaders
	Body       []byte
}

type CommonResponse_Status int32

const (
	CommonResponse_STATUS_UNSPECIFIED  CommonResponse_Status = 0
	CommonResponse_CONTINUE_PROCESSING CommonResponse_Status = 1
	CommonResponse_DENY_REQUEST        CommonResponse_Status = 2
)

func (s CommonResponse_Status) String() string {
	switch s {
	case CommonResponse_CONTINUE_PROCESSING:
		return "CONTINUE_PROCESSING"
	case CommonResponse_DENY_REQUEST:
		return "DENY_REQUEST"
	default:
		return "STATUS_UNSPECIFIED"
	}
}

type CommonResponse struct {
	Status             CommonResponse_Status
	HeadersToAdd       *HttpHeaders
	BodyOverride       []byte
	StatusCodeOverride int32
}
