package apicomm

type Result struct {
	// Informational message
	Message string `json:"message,omitempty"`
	// Error code
	Code int `json:"code,omitempty"`
}

// Data struct sent back for streaming (chunked) commands.
// Contains a data payload for incremental data, and a result
// payload for an error result. Only one of the two will be used
// in each chunk.

type StreamPayload struct {
	Data   interface{} `json:"data,omitempty"`
	Result *Result     `json:"result,omitempty"`
}

type WSStreamPayload struct {
	Code int         `json:"code"`
	Data interface{} `json:"data"`
}
