package conformance

// ProbeVector is one serialised value of the link-probe surface and whether it
// is acceptable. Two tables use it, because the surface has two halves with
// different subjects:
//
//   - ProbeTransitVectors: a protocol.Transit, held to ValidateTransit. The
//     settings are validated in the context of the Transit around them, so the
//     subject is the whole Transit and not the settings block.
//   - ProbeResultVectors: the protocol.NodeReport.Probes array, held to
//     ValidateProbeResults.
//
// The subject is the raw JSON for the reason AuditVector gives: a type error
// must cost a peer the same thing a validation error does. A peer holds the
// vector to the whole path:
//
//	var transit protocol.Transit
//	err := json.Unmarshal([]byte(vector.JSON), &transit)
//	if err == nil {
//		err = protocol.ValidateTransit(&transit)
//	}
//	// err == nil exactly when vector.Valid
//
// The expected values are written from the rules, not copied from the code:
// each name states the rule it pins. Append to the tables; never edit a
// verdict to make an implementation pass.
type ProbeVector struct {
	Name  string
	JSON  string
	Valid bool
}

const probeForwardUDP = `{"key":"fwd_7","port":20443,"target":"landing.example.com","target_port":443,"network":"tcp,udp"}`

const probeForward = `{"key":"fwd_7","port":20443,"target":"landing.example.com","target_port":443,"network":"tcp"}`

// ProbeTransitVectors is the shared table for Transit.Probe.
var ProbeTransitVectors = []ProbeVector{
	{Name: "forward probed by tcp", Valid: true,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "forward probed by quic", Valid: true,
		JSON: `{"forwards":[` + probeForwardUDP + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"quic"}]}}`},
	{Name: "forwards present but none probed", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000}}`},
	{Name: "interval at the floor", Valid: true,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":30,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "interval at the ceiling", Valid: true,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":3600,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "timeout at the floor", Valid: true,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":500,"forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "timeout at the ceiling", Valid: true,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":10000,"forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "https link url", Valid: true,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"link_url":"https://www.gstatic.com/generate_204","forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "http link url", Valid: true,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"link_url":"http://probe.example.com:8080/ping?x=1","forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "interval below the floor", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":29,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "interval above the ceiling", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":3601,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "interval omitted", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "timeout below the floor", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":499,"forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "timeout above the ceiling", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":10001,"forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "link url with a ftp scheme", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"link_url":"ftp://example.com/x","forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "link url that is relative", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"link_url":"/generate_204","forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "link url without a host", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"link_url":"https:///x","forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "link url with credentials", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"link_url":"https://user:pw@example.com/","forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "link url with a space", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"link_url":"https://example.com/a b","forwards":[{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "probe names a forward that is not in the transit", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"forwards":[{"key":"fwd_8","method":"tcp"}]}}`},
	{Name: "probe names a forward twice", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"tcp"},{"key":"fwd_7","method":"tcp"}]}}`},
	{Name: "probe method udp", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"udp"}]}}`},
	{Name: "probe forward key of a listener", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"forwards":[{"key":"lst_7","method":"tcp"}]}}`},
	{Name: "quic probe of a tcp-only forward", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"quic"}]}}`},
	{Name: "settings with a link out and no forward named", Valid: true,
		JSON: `{"links_out":[{"key":"lnk_3","address":"exit.example.com","port":30001,"protocol":"ss2022","ss":{"method":"2022-blake3-aes-128-gcm","password":"glwKkLUrNxQ4VbjbZG4svg=="}}],"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000}}`},
	{Name: "probe with nothing to probe", Valid: false,
		JSON: `{"probe":{"interval_seconds":60,"timeout_ms":3000}}`},
}

// ProbeResultVectors is the shared table for NodeReport.Probes.
var ProbeResultVectors = []ProbeVector{
	{Name: "no results", Valid: true, JSON: `[]`},
	{Name: "e2e result", Valid: true,
		JSON: `[{"key":"lnk_3","kind":"e2e","attempts":10,"failures":1,"rtt_min_ms":40,"rtt_median_ms":55,"rtt_max_ms":120,"last_error":"timeout","last_success_ms":1700000000000}]`},
	{Name: "transport result", Valid: true,
		JSON: `[{"key":"lnk_3","kind":"transport","attempts":10,"failures":0,"rtt_min_ms":10,"rtt_median_ms":10,"rtt_max_ms":10}]`},
	{Name: "forward result", Valid: true,
		JSON: `[{"key":"fwd_7","kind":"forward","attempts":10,"failures":0,"rtt_min_ms":10,"rtt_median_ms":12,"rtt_max_ms":30}]`},
	{Name: "e2e and transport of one link are two results", Valid: true,
		JSON: `[{"key":"lnk_3","kind":"e2e","attempts":1,"failures":0,"rtt_min_ms":5,"rtt_median_ms":5,"rtt_max_ms":5},{"key":"lnk_3","kind":"transport","attempts":1,"failures":0,"rtt_min_ms":4,"rtt_median_ms":4,"rtt_max_ms":4}]`},
	{Name: "every attempt failed with zero RTTs", Valid: true,
		JSON: `[{"key":"lnk_3","kind":"e2e","attempts":5,"failures":5,"rtt_min_ms":0,"rtt_median_ms":0,"rtt_max_ms":0,"last_error":"refused"}]`},
	{Name: "no attempts yet", Valid: true,
		JSON: `[{"key":"fwd_7","kind":"forward","attempts":0,"failures":0,"rtt_min_ms":0,"rtt_median_ms":0,"rtt_max_ms":0}]`},
	{Name: "attempts at the limit", Valid: true,
		JSON: `[{"key":"fwd_7","kind":"forward","attempts":1000,"failures":0,"rtt_min_ms":1,"rtt_median_ms":2,"rtt_max_ms":3}]`},
	{Name: "probe_unavailable error class", Valid: true,
		JSON: `[{"key":"lnk_3","kind":"e2e","attempts":1,"failures":1,"rtt_min_ms":0,"rtt_median_ms":0,"rtt_max_ms":0,"last_error":"probe_unavailable"}]`},
	{Name: "attempts above the limit", Valid: false,
		JSON: `[{"key":"fwd_7","kind":"forward","attempts":1001,"failures":0,"rtt_min_ms":1,"rtt_median_ms":2,"rtt_max_ms":3}]`},
	{Name: "failures above attempts", Valid: false,
		JSON: `[{"key":"fwd_7","kind":"forward","attempts":2,"failures":3,"rtt_min_ms":0,"rtt_median_ms":0,"rtt_max_ms":0}]`},
	{Name: "negative failures", Valid: false,
		JSON: `[{"key":"fwd_7","kind":"forward","attempts":2,"failures":-1,"rtt_min_ms":1,"rtt_median_ms":1,"rtt_max_ms":1}]`},
	{Name: "min above median", Valid: false,
		JSON: `[{"key":"fwd_7","kind":"forward","attempts":2,"failures":0,"rtt_min_ms":9,"rtt_median_ms":5,"rtt_max_ms":10}]`},
	{Name: "median above max", Valid: false,
		JSON: `[{"key":"fwd_7","kind":"forward","attempts":2,"failures":0,"rtt_min_ms":1,"rtt_median_ms":11,"rtt_max_ms":10}]`},
	{Name: "negative rtt", Valid: false,
		JSON: `[{"key":"fwd_7","kind":"forward","attempts":2,"failures":0,"rtt_min_ms":-1,"rtt_median_ms":5,"rtt_max_ms":10}]`},
	{Name: "rtt on a result where every attempt failed", Valid: false,
		JSON: `[{"key":"fwd_7","kind":"forward","attempts":2,"failures":2,"rtt_min_ms":1,"rtt_median_ms":1,"rtt_max_ms":1}]`},
	{Name: "e2e on a forward key", Valid: false,
		JSON: `[{"key":"fwd_7","kind":"e2e","attempts":1,"failures":0,"rtt_min_ms":1,"rtt_median_ms":1,"rtt_max_ms":1}]`},
	{Name: "transport on a forward key", Valid: false,
		JSON: `[{"key":"fwd_7","kind":"transport","attempts":1,"failures":0,"rtt_min_ms":1,"rtt_median_ms":1,"rtt_max_ms":1}]`},
	{Name: "forward kind on a link key", Valid: false,
		JSON: `[{"key":"lnk_3","kind":"forward","attempts":1,"failures":0,"rtt_min_ms":1,"rtt_median_ms":1,"rtt_max_ms":1}]`},
	{Name: "key of a listener", Valid: false,
		JSON: `[{"key":"lst_3","kind":"e2e","attempts":1,"failures":0,"rtt_min_ms":1,"rtt_median_ms":1,"rtt_max_ms":1}]`},
	{Name: "non-canonical link key", Valid: false,
		JSON: `[{"key":"lnk_03","kind":"e2e","attempts":1,"failures":0,"rtt_min_ms":1,"rtt_median_ms":1,"rtt_max_ms":1}]`},
	{Name: "unknown kind", Valid: false,
		JSON: `[{"key":"lnk_3","kind":"icmp","attempts":1,"failures":0,"rtt_min_ms":1,"rtt_median_ms":1,"rtt_max_ms":1}]`},
	{Name: "unknown error class", Valid: false,
		JSON: `[{"key":"lnk_3","kind":"e2e","attempts":1,"failures":1,"rtt_min_ms":0,"rtt_median_ms":0,"rtt_max_ms":0,"last_error":"connection reset by peer"}]`},
	{Name: "negative last success", Valid: false,
		JSON: `[{"key":"lnk_3","kind":"e2e","attempts":1,"failures":0,"rtt_min_ms":1,"rtt_median_ms":1,"rtt_max_ms":1,"last_success_ms":-1}]`},
	{Name: "duplicate key and kind", Valid: false,
		JSON: `[{"key":"lnk_3","kind":"e2e","attempts":1,"failures":0,"rtt_min_ms":1,"rtt_median_ms":1,"rtt_max_ms":1},{"key":"lnk_3","kind":"e2e","attempts":1,"failures":0,"rtt_min_ms":1,"rtt_median_ms":1,"rtt_max_ms":1}]`},
	{Name: "attempts that is a string", Valid: false,
		JSON: `[{"key":"lnk_3","kind":"e2e","attempts":"1","failures":0,"rtt_min_ms":1,"rtt_median_ms":1,"rtt_max_ms":1}]`},
}
