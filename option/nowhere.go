package option

// NowhereOutboundOptions is the JSON configuration for a Nowhere v1 outbound.
//
// Example:
//
//	{
//	  "type": "nowhere",
//	  "tag": "proxy",
//	  "server": "47.239.125.83",
//	  "server_port": 11111,
//	  "key": "c6f6ef3be9716d3e4a0cdc37d3e9bb16",
//	  "spec": "ef6ddf6c224d0dc8e77ee7e521a8509a",
//	  "alpn": "a04d46d2ae12d791",
//	  "tls": { "insecure": true }
//	}
type NowhereOutboundOptions struct {
	DialerOptions
	ServerOptions
	// Key is the shared secret for authentication (required).
	Key string `json:"key"`
	// Spec is the protocol specification string.
	// If empty, it defaults to the key value for HKDF derivation.
	Spec string `json:"spec,omitempty"`
	// ALPN overrides the HKDF-derived ALPN string.
	// Must match the server's configured alpn parameter.
	ALPN string `json:"alpn,omitempty"`
	// TLS holds TLS settings. InsecureSkipVerify is recommended
	// since nowhere servers use self-signed certificates.
	TLS *OutboundTLSOptions `json:"tls,omitempty"`
}
