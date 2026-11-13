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
		for need := 0; need < 4; need++ {
			fuzz.Add([]byte(seed), uint8(need))
		}
	}
	fuzz.Fuzz(func(t *testing.T, raw []byte, needBits uint8) {
		need := SniffNeed(needBits & 3)
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
