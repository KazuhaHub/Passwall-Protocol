package protocol

import "testing"

// FuzzCheckXraySniffing is the inbound's sniffing object as an operator wrote
// it, which can be any JSON at all. The verdict's shape must hold for all of it.
func FuzzCheckXraySniffing(fuzz *testing.F) {
	for _, seed := range []string{
		``, `null`, `{}`, `{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":false}`,
		`{"enabled":true,"destOverride":"http,tls,quic"}`, `{"enabled":true,"metadataOnly":true}`,
		`{"enabled":true,"destOverride":["http","tls","quic"],"domainsExcluded":["full:a"],"ipsExcluded":"10.0.0.0/8"}`,
		`{"enabled":true,"destOverride":["bogus"]}`, `[`, `"x"`,
	} {
		for need := 0; need < 8; need++ {
			fuzz.Add([]byte(seed), uint8(need))
		}
	}
	fuzz.Fuzz(func(t *testing.T, raw []byte, needBits uint8) {
		need := SniffNeed(needBits & 7)
		verdict, reason, err := CheckXraySniffing(raw, need)
		if need == 0 {
			if err != nil || verdict != SniffOK || reason != "" {
				t.Fatalf("need 0 must be ok: %s %q %v", verdict, reason, err)
			}
			return
		}
		if err != nil {
			if verdict != "" || reason != "" {
				t.Fatalf("an error carries no verdict: %s %q", verdict, reason)
			}
			return
		}
		switch verdict {
		case SniffOK:
			if reason != "" {
				t.Fatalf("ok has no reason: %q", reason)
			}
		case SniffInject, SniffInsufficient:
			if reason == "" {
				t.Fatalf("%s needs a reason", verdict)
			}
		default:
			t.Fatalf("verdict %q", verdict)
		}
		// Asking for less can never be harder to satisfy.
		if need == SniffForDomains|SniffForProtocols && verdict == SniffOK {
			if v, _, err := CheckXraySniffing(raw, SniffForProtocols); err != nil || v != SniffOK {
				t.Fatalf("domains+protocols ok but protocols alone is %s (%v)", v, err)
			}
		}
	})
}

// The injected object is what a node writes into an inbound whose sniffing is
// off, so it must be valid JSON that its own check calls sufficient for domain
// rules, and it must say routeOnly false in so many words.
func TestXraySniffingInjectionSatisfiesItsOwnCheck(t *testing.T) {
	injected := XraySniffingInjection()
	if injected != `{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":false}` {
		t.Fatalf("injection = %s", injected)
	}
	verdict, reason, err := CheckXraySniffing([]byte(injected), SniffForDomains|SniffForProtocols)
	if err != nil || verdict != SniffOK {
		t.Fatalf("the injection fails its own check: %s %q %v", verdict, reason, err)
	}
}

// SniffForResolvedIPs is about IPOnDemand routing: Xray resolves the name the
// router sees, and with routeOnly the sniffed name replaces the real target for
// that resolution while the connection still goes to the real address. Sniffing
// that is off supplies nothing and the node injects nothing for this need.
func TestCheckXraySniffing_ResolvedIPs(t *testing.T) {
	const resolved = SniffForResolvedIPs
	for _, tc := range []struct {
		name    string
		raw     string
		need    SniffNeed
		verdict SniffVerdict
		reason  string
	}{
		{"absent", ``, resolved, SniffOK, ""},
		{"disabled", `{"enabled":false}`, resolved, SniffOK, ""},
		{"enabled, routeOnly false", `{"enabled":true,"routeOnly":false}`, resolved, SniffOK, ""},
		{"metadataOnly", `{"enabled":true,"metadataOnly":true}`, resolved, SniffOK, ""},
		{"routeOnly with an empty override", `{"enabled":true,"routeOnly":true}`, resolved, SniffOK, ""},
		{"routeOnly with http", `{"enabled":true,"destOverride":["http"],"routeOnly":true}`, resolved, SniffInsufficient, "route_only_resolve"},
		{"routeOnly with an empty override never sets a route target", `{"enabled":true,"destOverride":[],"routeOnly":true}`, resolved, SniffOK, ""},
		{"routeOnly with fakedns only never sets a route target", `{"enabled":true,"destOverride":["fakedns"],"routeOnly":true}`, resolved, SniffOK, ""},
		{"routeOnly with fakedns+others never sets a route target", `{"enabled":true,"destOverride":["fakedns+others"],"routeOnly":true}`, resolved, SniffOK, ""},
		{"routeOnly with fakedns+others and tls", `{"enabled":true,"destOverride":["FakeDNS+Others","tls"],"routeOnly":true}`, resolved, SniffInsufficient, "route_only_resolve"},
		{"routeOnly with fakedns and http", `{"enabled":true,"destOverride":["fakedns","http"],"routeOnly":true}`, resolved, SniffInsufficient, "route_only_resolve"},
		{"routeOnly with a full override", `{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}`, resolved, SniffInsufficient, "route_only_resolve"},
		{"disabled with domains is still injected", `{"enabled":false}`, resolved | SniffForDomains, SniffInject, "sniffing_disabled"},
		{"domains, routeOnly keeps the domain reason", `{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}`, resolved | SniffForDomains, SniffInsufficient, "route_only"},
		{"domains satisfied", `{"enabled":true,"destOverride":["http","tls","quic"]}`, resolved | SniffForDomains, SniffOK, ""},
		{"metadataOnly with domains", `{"enabled":true,"metadataOnly":true}`, resolved | SniffForDomains, SniffInsufficient, "metadata_only"},
		{"metadataOnly with protocols", `{"enabled":true,"metadataOnly":true}`, resolved | SniffForProtocols, SniffInsufficient, "metadata_only"},
		{"protocols with routeOnly and tls", `{"enabled":true,"destOverride":["tls"],"routeOnly":true}`, resolved | SniffForProtocols, SniffInsufficient, "route_only_resolve"},
		{"protocols, disabled", `{"enabled":false}`, resolved | SniffForProtocols, SniffInject, "sniffing_disabled"},
		{"protocols alone with routeOnly is unchanged", `{"enabled":true,"routeOnly":true}`, SniffForProtocols, SniffOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict, reason, err := CheckXraySniffing([]byte(tc.raw), tc.need)
			if err != nil || verdict != tc.verdict || reason != tc.reason {
				t.Fatalf("got (%s, %q, %v), want (%s, %q)", verdict, reason, err, tc.verdict, tc.reason)
			}
		})
	}
	// Malformed input is refused whatever the need.
	if _, _, err := CheckXraySniffing([]byte(`{"enabled":`), resolved); err == nil {
		t.Fatal("malformed sniffing accepted")
	}
	if _, _, err := CheckXraySniffing([]byte(`{"enabled":false,"destOverride":["bogus"]}`), resolved); err == nil {
		t.Fatal("unloadable sniffing accepted")
	}
}
