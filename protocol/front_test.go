package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func frontForward(id int64) Forward {
	forward := validForward()
	forward.Key = NewForwardKey(id)
	forward.Port = 443
	return forward
}

func frontLink(id int64) LinkIn {
	link := realityLinkIn(id)
	link.Port = 443
	return link
}

// frontedTransit is a front on the shared port 443 with every kind of target:
// two fronted listeners, a forward, a link, and a default listener.
func frontedTransit() *Transit {
	return &Transit{
		Forwards: []Forward{frontForward(7)},
		LinksIn:  []LinkIn{frontLink(2)},
		Fronts: []Front{{
			Key: NewFrontKey(1), Port: 443,
			Listeners: []FrontedListener{
				{Listener: NewListenerKey(1), LoopbackPort: 20001},
				{Listener: NewListenerKey(2), LoopbackPort: 20002},
			},
			Routes: []FrontRoute{
				{ServerNames: []string{"a.example.com"}, Target: FrontTarget{Listener: NewListenerKey(1)}},
				{ServerNames: []string{"b.example.com", "c.example.com"}, Target: FrontTarget{Forward: NewForwardKey(7)}},
				{ServerNames: []string{"www.example.com"}, Target: FrontTarget{Link: NewLinkKey(2)}},
			},
			Default: FrontTarget{Listener: NewListenerKey(2)},
		}},
	}
}

func TestSNICapabilityName(t *testing.T) {
	if CapabilityTransitSNI != "transit.sni.v1" {
		t.Fatalf("capability name changed: %q", CapabilityTransitSNI)
	}
	for _, upgrade := range AgentUpgradeCapabilities() {
		if upgrade == CapabilityTransitSNI {
			t.Fatalf("%s is an upgrade capability", upgrade)
		}
	}
}

func TestFrontKeyIsItsOwnType(t *testing.T) {
	key := NewFrontKey(5)
	if key != "fnt_5" {
		t.Fatalf("minted %q", key)
	}
	if id, err := key.RowID(); err != nil || id != 5 {
		t.Fatalf("RowID = %d, %v", id, err)
	}
	for _, other := range []func() error{
		func() error { _, err := ListenerKey(key).RowID(); return err },
		func() error { _, err := ForwardKey(key).RowID(); return err },
		func() error { _, err := LinkKey(key).RowID(); return err },
	} {
		if other() == nil {
			t.Fatal("a front key parsed as another family's key")
		}
	}
	if _, err := FrontKey("fnt_05").RowID(); err == nil {
		t.Fatal("non-canonical front key accepted")
	}
}

func cloneTransit(t *testing.T, transit *Transit) *Transit {
	t.Helper()
	raw, err := json.Marshal(transit)
	if err != nil {
		t.Fatal(err)
	}
	var copy Transit
	if err := json.Unmarshal(raw, &copy); err != nil {
		t.Fatal(err)
	}
	return &copy
}

func TestValidateFronts(t *testing.T) {
	valid := frontedTransit()
	if err := ValidateTransit(valid); err != nil {
		t.Fatalf("valid transit: %v", err)
	}

	// An external default, a listener that is both a route target and the
	// default, and a bound address.
	external := frontedTransit()
	external.Fronts[0].Default = FrontTarget{External: &FrontExternal{Host: "www.example.org", Port: 443}}
	external.Fronts[0].Listeners = external.Fronts[0].Listeners[:1]
	if err := ValidateTransit(external); err != nil {
		t.Fatalf("external default: %v", err)
	}
	both := frontedTransit()
	both.Fronts[0].Default = FrontTarget{Listener: NewListenerKey(1)}
	both.Fronts[0].Listeners = both.Fronts[0].Listeners[:1]
	if err := ValidateTransit(both); err != nil {
		t.Fatalf("a listener that is a route target and the default: %v", err)
	}
	// Two fronts on distinct specific addresses of one port do not share a bind.
	two := frontedTransit()
	two.Forwards, two.LinksIn = nil, nil
	two.Fronts[0].Listen = "203.0.113.5"
	two.Fronts[0].Routes = two.Fronts[0].Routes[:1]
	two.Fronts = append(two.Fronts, Front{
		Key: NewFrontKey(2), Listen: "203.0.113.6", Port: 443,
		Listeners: []FrontedListener{{Listener: NewListenerKey(3), LoopbackPort: 20003}},
		Routes:    []FrontRoute{{ServerNames: []string{"x.example.com"}, Target: FrontTarget{Listener: NewListenerKey(3)}}},
		Default:   FrontTarget{External: &FrontExternal{Host: "203.0.113.9", Port: 443}},
	})
	if err := ValidateTransit(two); err != nil {
		t.Fatalf("two fronts on distinct addresses: %v", err)
	}
	// An external on another port of the front's own host is not a loop.
	elsewhere := frontedTransit()
	elsewhere.Fronts[0].Listen = "203.0.113.5"
	elsewhere.Forwards[0].Listen = "203.0.113.5"
	elsewhere.LinksIn[0].Listen = "203.0.113.5"
	elsewhere.Fronts[0].Listeners = elsewhere.Fronts[0].Listeners[:1]
	elsewhere.Fronts[0].Default = FrontTarget{External: &FrontExternal{Host: "203.0.113.9", Port: 8080}}
	if err := ValidateTransit(elsewhere); err != nil {
		t.Fatalf("external on another port: %v", err)
	}

	front := func(tr *Transit) *Front { return &tr.Fronts[0] }
	bad := map[string]func(*Transit){
		"key of a forward":           func(tr *Transit) { front(tr).Key = "fwd_1" },
		"key not canonical":          func(tr *Transit) { front(tr).Key = "fnt_01" },
		"noncanonical listen":        func(tr *Transit) { front(tr).Listen = "2001:0db8::1" },
		"port zero":                  func(tr *Transit) { front(tr).Port = 0 },
		"port too large":             func(tr *Transit) { front(tr).Port = 65536 },
		"no routes":                  func(tr *Transit) { front(tr).Routes = nil },
		"default missing":            func(tr *Transit) { front(tr).Default = FrontTarget{} },
		"default names two targets":  func(tr *Transit) { front(tr).Default.Forward = NewForwardKey(7) },
		"route target names nothing": func(tr *Transit) { front(tr).Routes[0].Target = FrontTarget{} },
		"route target names two": func(tr *Transit) {
			front(tr).Routes[0].Target.Link = NewLinkKey(2)
		},
		"route with no names":         func(tr *Transit) { front(tr).Routes[0].ServerNames = nil },
		"names out of order":          func(tr *Transit) { front(tr).Routes[1].ServerNames = []string{"c.example.com", "b.example.com"} },
		"name twice in a route":       func(tr *Transit) { front(tr).Routes[1].ServerNames = []string{"b.example.com", "b.example.com"} },
		"name in two routes":          func(tr *Transit) { front(tr).Routes[2].ServerNames = []string{"b.example.com"} },
		"uppercase name":              func(tr *Transit) { front(tr).Routes[0].ServerNames = []string{"A.example.com"} },
		"wildcard name":               func(tr *Transit) { front(tr).Routes[0].ServerNames = []string{"*.example.com"} },
		"address as a name":           func(tr *Transit) { front(tr).Routes[0].ServerNames = []string{"203.0.113.1"} },
		"single label name":           func(tr *Transit) { front(tr).Routes[0].ServerNames = []string{"localhost"} },
		"listener target not fronted": func(tr *Transit) { front(tr).Routes[0].Target.Listener = NewListenerKey(9) },
		"listener target not a listener": func(tr *Transit) {
			front(tr).Routes[0].Target.Listener = "fwd_7"
		},
		"fronted listener unused": func(tr *Transit) {
			front(tr).Listeners = append(front(tr).Listeners, FrontedListener{Listener: NewListenerKey(3), LoopbackPort: 20003})
		},
		"fronted listener twice": func(tr *Transit) {
			front(tr).Listeners = append(front(tr).Listeners, FrontedListener{Listener: NewListenerKey(1), LoopbackPort: 20003})
		},
		"loopback port zero":       func(tr *Transit) { front(tr).Listeners[0].LoopbackPort = 0 },
		"loopback port too large":  func(tr *Transit) { front(tr).Listeners[0].LoopbackPort = 70000 },
		"loopback port repeated":   func(tr *Transit) { front(tr).Listeners[1].LoopbackPort = 20001 },
		"loopback port is a front": func(tr *Transit) { front(tr).Listeners[1].LoopbackPort = 443 },
		"forward target unknown":   func(tr *Transit) { front(tr).Routes[1].Target.Forward = NewForwardKey(8) },
		"forward target is udp too": func(tr *Transit) {
			tr.Forwards[0].Network = ForwardNetworkTCPUDP
		},
		"forward on another port": func(tr *Transit) { tr.Forwards[0].Port = 444 },
		"forward on another address": func(tr *Transit) {
			tr.Forwards[0].Listen = "203.0.113.5"
		},
		"link target unknown":   func(tr *Transit) { front(tr).Routes[2].Target.Link = NewLinkKey(3) },
		"link target is ss2022": func(tr *Transit) { tr.LinksIn[0] = ssLinkIn(2, 443) },
		"link on another port":  func(tr *Transit) { tr.LinksIn[0].Port = 30443 },
		"external in a route": func(tr *Transit) {
			front(tr).Routes[0].Target = FrontTarget{External: &FrontExternal{Host: "www.example.org", Port: 443}}
		},
		"external host with port": func(tr *Transit) {
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "www.example.org:443", Port: 443}}
		},
		"external host uppercase": func(tr *Transit) {
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "WWW.example.org", Port: 443}}
		},
		"external port zero": func(tr *Transit) {
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "www.example.org", Port: 0}}
		},
		"external loops to loopback": func(tr *Transit) {
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "127.0.0.1", Port: 443}}
		},
		"external loops to ::1": func(tr *Transit) {
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "::1", Port: 443}}
		},
		"external loops to unspecified": func(tr *Transit) {
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "0.0.0.0", Port: 443}}
		},
		"external loops to localhost": func(tr *Transit) {
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "localhost", Port: 443}}
		},
		"external loops to the listen host": func(tr *Transit) {
			front(tr).Listen = "203.0.113.5"
			tr.Forwards[0].Listen = "203.0.113.5"
			tr.LinksIn[0].Listen = "203.0.113.5"
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "203.0.113.5", Port: 443}}
		},
		"external to another front's bind": func(tr *Transit) {
			front(tr).Port = 443
			tr.Fronts = append(tr.Fronts, Front{
				Key: NewFrontKey(2), Listen: "203.0.113.5", Port: 8443,
				Listeners: []FrontedListener{{Listener: NewListenerKey(5), LoopbackPort: 20005}},
				Routes:    []FrontRoute{{ServerNames: []string{"x.example.com"}, Target: FrontTarget{Listener: NewListenerKey(5)}}},
				Default:   FrontTarget{External: &FrontExternal{Host: "www.example.org", Port: 443}},
			})
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "203.0.113.5", Port: 8443}}
		},
		"external to a mapped spelling of the listen address": func(tr *Transit) {
			front(tr).Listen = "::ffff:203.0.113.5"
			tr.Forwards[0].Listen = "::ffff:203.0.113.5"
			tr.LinksIn[0].Listen = "::ffff:203.0.113.5"
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "203.0.113.5", Port: 443}}
		},
		"external to a forward's bind": func(tr *Transit) {
			front(tr).Listen = "203.0.113.5"
			tr.Forwards[0].Listen = "203.0.113.5"
			tr.LinksIn[0].Listen = "203.0.113.5"
			loop := validForward()
			loop.Key, loop.Listen, loop.Port = NewForwardKey(8), "203.0.113.5", 8443
			loop.Target, loop.TargetPort = "203.0.113.5", 443
			tr.Forwards = append(tr.Forwards, loop)
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "203.0.113.5", Port: 8443}}
		},
		"external to a link's bind": func(tr *Transit) {
			link := ssLinkIn(5, 8443)
			link.Listen = "203.0.113.9"
			tr.LinksIn = append(tr.LinksIn, link)
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "203.0.113.9", Port: 8443}}
		},
		"external in 0.0.0.0/8": func(tr *Transit) {
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "0.1.2.3", Port: 8080}}
		},
		"external to loopback on another port": func(tr *Transit) {
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "127.0.0.1", Port: 8080}}
		},
		"external to localhost on another port": func(tr *Transit) {
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "localhost", Port: 8080}}
		},
		"external to the unspecified address on another port": func(tr *Transit) {
			front(tr).Default = FrontTarget{External: &FrontExternal{Host: "::", Port: 8080}}
		},
		"link route names a name the link does not serve": func(tr *Transit) {
			front(tr).Routes[2].ServerNames = []string{"d.example.com"}
		},
		"link name routed to another target": func(tr *Transit) {
			tr.LinksIn[0].Reality.ServerNames = []string{"www.example.com", "www2.example.com"}
		},
		"forward on the front's bind that is not its target": func(tr *Transit) {
			tr.Forwards = append(tr.Forwards, frontForward(8))
		},
		"link on the front's bind that is not its target": func(tr *Transit) {
			tr.LinksIn = append(tr.LinksIn, frontLink(3))
		},
		"forward on a wildcard bind over the front's address": func(tr *Transit) {
			front(tr).Listen = "203.0.113.5"
			tr.Forwards[0].Listen = "203.0.113.5"
			tr.LinksIn[0].Listen = "203.0.113.5"
			other := frontForward(8)
			other.Listen = "0.0.0.0"
			tr.Forwards = append(tr.Forwards, other)
		},
		"loopback port of a forward on every address": func(tr *Transit) {
			other := validForward()
			other.Key, other.Port = NewForwardKey(8), 20001
			tr.Forwards = append(tr.Forwards, other)
		},
		"loopback port of a link on 0.0.0.0": func(tr *Transit) {
			other := ssLinkIn(5, 20002)
			other.Listen = "0.0.0.0"
			tr.LinksIn = append(tr.LinksIn, other)
		},
		"loopback port of a forward on 127.0.0.2": func(tr *Transit) {
			other := validForward()
			other.Key, other.Port, other.Listen = NewForwardKey(8), 20001, "127.0.0.2"
			tr.Forwards = append(tr.Forwards, other)
		},
		"two fronts on one bind": func(tr *Transit) {
			tr.Fronts = append(tr.Fronts, Front{
				Key: NewFrontKey(2), Port: 443,
				Routes:  []FrontRoute{{ServerNames: []string{"x.example.com"}, Target: FrontTarget{External: nil, Listener: NewListenerKey(5)}}},
				Default: FrontTarget{External: &FrontExternal{Host: "www.example.org", Port: 443}},
			})
		},
		"wildcard front over a specific one": func(tr *Transit) {
			front(tr).Listen = "203.0.113.5"
			tr.Forwards[0].Listen = "203.0.113.5"
			tr.LinksIn[0].Listen = "203.0.113.5"
			tr.Fronts = append(tr.Fronts, Front{
				Key: NewFrontKey(2), Port: 443,
				Listeners: []FrontedListener{{Listener: NewListenerKey(5), LoopbackPort: 20005}},
				Routes:    []FrontRoute{{ServerNames: []string{"x.example.com"}, Target: FrontTarget{Listener: NewListenerKey(5)}}},
				Default:   FrontTarget{External: &FrontExternal{Host: "www.example.org", Port: 443}},
			})
		},
		"same key twice": func(tr *Transit) {
			tr.Fronts = append(tr.Fronts, Front{
				Key: NewFrontKey(1), Port: 8443,
				Listeners: []FrontedListener{{Listener: NewListenerKey(5), LoopbackPort: 20005}},
				Routes:    []FrontRoute{{ServerNames: []string{"x.example.com"}, Target: FrontTarget{Listener: NewListenerKey(5)}}},
				Default:   FrontTarget{External: &FrontExternal{Host: "www.example.org", Port: 443}},
			})
		},
		"listener behind two fronts": func(tr *Transit) {
			tr.Fronts = append(tr.Fronts, Front{
				Key: NewFrontKey(2), Port: 8443,
				Listeners: []FrontedListener{{Listener: NewListenerKey(1), LoopbackPort: 20005}},
				Routes:    []FrontRoute{{ServerNames: []string{"x.example.com"}, Target: FrontTarget{Listener: NewListenerKey(1)}}},
				Default:   FrontTarget{External: &FrontExternal{Host: "www.example.org", Port: 443}},
			})
		},
		"loopback port shared by two fronts": func(tr *Transit) {
			tr.Fronts = append(tr.Fronts, Front{
				Key: NewFrontKey(2), Port: 8443,
				Listeners: []FrontedListener{{Listener: NewListenerKey(5), LoopbackPort: 20001}},
				Routes:    []FrontRoute{{ServerNames: []string{"x.example.com"}, Target: FrontTarget{Listener: NewListenerKey(5)}}},
				Default:   FrontTarget{External: &FrontExternal{Host: "www.example.org", Port: 443}},
			})
		},
		"too many routes": func(tr *Transit) {
			front(tr).Routes = nil
			for i := 0; i <= MaxFrontRoutes; i++ {
				front(tr).Routes = append(front(tr).Routes, FrontRoute{
					ServerNames: []string{"h" + strings.Repeat("a", i%50) + string(rune('a'+i/50)) + ".example.com"},
					Target:      FrontTarget{Listener: NewListenerKey(1)},
				})
			}
		},
		"too many names in a route": func(tr *Transit) {
			front(tr).Routes[0].ServerNames = nil
			for i := 0; i <= MaxFrontRouteNames; i++ {
				front(tr).Routes[0].ServerNames = append(front(tr).Routes[0].ServerNames, "n"+string(rune('a'+i))+".example.com")
			}
		},
	}
	for name, mutate := range bad {
		copy := cloneTransit(t, valid)
		mutate(copy)
		if err := ValidateTransit(copy); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTooManyFronts(t *testing.T) {
	transit := &Transit{}
	for i := 1; i <= MaxFronts+1; i++ {
		transit.Fronts = append(transit.Fronts, Front{
			Key: NewFrontKey(int64(i)), Port: 1000 + i,
			Listeners: []FrontedListener{{Listener: NewListenerKey(int64(i)), LoopbackPort: 30000 + i}},
			Routes:    []FrontRoute{{ServerNames: []string{"x.example.com"}, Target: FrontTarget{Listener: NewListenerKey(int64(i))}}},
			Default:   FrontTarget{External: &FrontExternal{Host: "www.example.org", Port: 443}},
		})
	}
	if err := ValidateTransit(transit); err == nil {
		t.Fatal("more than MaxFronts accepted")
	}
	transit.Fronts = transit.Fronts[:MaxFronts]
	if err := ValidateTransit(transit); err != nil {
		t.Fatalf("exactly MaxFronts: %v", err)
	}
}

func TestBindsOverlap(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"", "", true}, {"", "203.0.113.5", true}, {"203.0.113.5", "", true},
		{"203.0.113.5", "203.0.113.5", true}, {"203.0.113.5", "203.0.113.6", false},
		{"0.0.0.0", "203.0.113.5", true}, {"0.0.0.0", "2001:db8::1", false},
		{"::", "203.0.113.5", true}, {"::", "2001:db8::1", true}, {"::", "0.0.0.0", true},
		{"2001:db8::1", "2001:db8::2", false}, {"127.0.0.1", "0.0.0.0", true},
	} {
		if got := bindsOverlap(tc.a, tc.b); got != tc.want {
			t.Errorf("bindsOverlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		if got := bindsOverlap(tc.b, tc.a); got != tc.want {
			t.Errorf("bindsOverlap(%q, %q) = %v, want %v", tc.b, tc.a, got, tc.want)
		}
	}
}

func TestTLSProbeMethod(t *testing.T) {
	if ProbeMethodTLS != "tls" {
		t.Fatalf("method name changed: %q", ProbeMethodTLS)
	}
	transit := frontedTransit()
	transit.Probe = &ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000,
		Forwards: []ProbeTarget{{Key: NewForwardKey(7), Method: ProbeMethodTLS}}}
	if err := ValidateTransit(transit); err != nil {
		t.Fatalf("tls probe of a front route target: %v", err)
	}
	if err := ValidateProbeSettings(*transit.Probe); err != nil {
		t.Fatalf("tls method rejected in isolation: %v", err)
	}

	// A forward behind no front has no server name to send.
	plain := &Transit{Forwards: []Forward{validForward()}, Probe: &ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000,
		Forwards: []ProbeTarget{{Key: NewForwardKey(7), Method: ProbeMethodTLS}}}}
	if err := ValidateTransit(plain); err == nil {
		t.Error("tls probe of a forward that is no front target accepted")
	}
	// A forward that is only the default of a front is not a route target.
	onlyDefault := frontedTransit()
	onlyDefault.Fronts[0].Routes = onlyDefault.Fronts[0].Routes[:1]
	onlyDefault.LinksIn = nil
	onlyDefault.Fronts[0].Default = FrontTarget{Forward: NewForwardKey(7)}
	onlyDefault.Fronts[0].Listeners = onlyDefault.Fronts[0].Listeners[:1]
	onlyDefault.Probe = transit.Probe
	if err := ValidateTransit(onlyDefault); err == nil {
		t.Error("tls probe of a forward that is only a front default accepted")
	}
	onlyDefault.Probe = &ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000,
		Forwards: []ProbeTarget{{Key: NewForwardKey(7), Method: ProbeMethodTCP}}}
	if err := ValidateTransit(onlyDefault); err != nil {
		t.Errorf("tcp probe of a front default forward: %v", err)
	}
}

func TestFrontObjectsAreConfigObjects(t *testing.T) {
	report := NodeReport{AgentID: "a1", ProtocolVersion: ProtocolVersion1, Have: emptyHave()}
	report.Objects = []ObjectStatus{
		{Stream: StreamConfig, Key: string(NewFrontKey(3)), State: ObjectApplied, SinceVersion: Version{Epoch: 1, Version: 1}},
		{Stream: StreamConfig, Key: string(NewFrontKey(4)), State: ObjectRejected, SinceVersion: Version{Epoch: 1, Version: 1}, FirstFailedAtMS: 1, IssueCode: "core_config_rejected"},
	}
	if err := ValidateNodeReportBase(report); err != nil {
		t.Fatalf("front objects: %v", err)
	}
	for _, bad := range []ObjectStatus{
		{Stream: StreamRoster, Key: string(NewFrontKey(3)), State: ObjectApplied, SinceVersion: Version{Epoch: 1, Version: 1}},
		{Stream: StreamConfig, Key: "fnt_03", State: ObjectApplied, SinceVersion: Version{Epoch: 1, Version: 1}},
	} {
		report.Objects = []ObjectStatus{bad}
		if err := ValidateNodeReportBase(report); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// The golden string was written from the encoding before Fronts existed: a
// server that shares no port must keep producing exactly these bytes, or every
// agent in the fleet re-applies its config.
func TestTransitWithoutFrontsIsByteIdenticalToV09(t *testing.T) {
	transit := routedTransit()
	transit.Forwards = []Forward{validForward()}
	transit.Probe = &ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000, Forwards: []ProbeTarget{{Key: NewForwardKey(7), Method: ProbeMethodTCP}}}
	const want = `{"forwards":[{"key":"fwd_7","port":20443,"target":"landing.example.com","target_port":443,"network":"tcp"}],"links_out":[{"key":"lnk_3","address":"exit.example.com","port":30001,"protocol":"ss2022","ss":{"method":"2022-blake3-aes-128-gcm","password":"glwKkLUrNxQ4VbjbZG4svg=="}},{"key":"lnk_4","address":"203.0.113.20","port":30443,"protocol":"vless_reality","reality":{"uuid":"0f62f495-b5ca-4509-b6cd-54a040deafd5","public_key":"EHrIxc9qujEbp1w115n8nf4aBgOZD45iSDc9dCwYwB8","server_name":"www.example.com","short_id":"a1b2","fingerprint":"chrome"}}],"egress":[{"listener":"lst_1","link":"lnk_3"}],"probe":{"interval_seconds":60,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"tcp"}]},"routes":[{"listener":"lst_1","rules":[{"id":"r1","domains":["domain:netflix.com","keyword:nflx"],"exit":"lnk_4"},{"id":"r2","cidrs":["10.0.0.0/8"],"ports":"443","network":"tcp","exit":"local"}]}]}`
	got, err := json.Marshal(transit)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("transit without Fronts changed on the wire:\n got=%s\nwant=%s", got, want)
	}
	if strings.Contains(string(got), "fronts") {
		t.Fatal("an empty Fronts is encoded")
	}
}

func TestFrontEncoding(t *testing.T) {
	transit := Transit{Fronts: []Front{{
		Key: NewFrontKey(1), Port: 443,
		Listeners: []FrontedListener{{Listener: NewListenerKey(1), LoopbackPort: 20001}},
		Routes:    []FrontRoute{{ServerNames: []string{"a.example.com"}, Target: FrontTarget{Listener: NewListenerKey(1)}}},
		Default:   FrontTarget{External: &FrontExternal{Host: "www.example.org", Port: 443}},
	}}}
	const want = `{"fronts":[{"key":"fnt_1","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[{"server_names":["a.example.com"],"target":{"listener":"lst_1"}}],"default":{"external":{"host":"www.example.org","port":443}}}]}`
	got, err := json.Marshal(transit)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("front encoding changed:\n got=%s\nwant=%s", got, want)
	}
}

func TestFrontBindsAreNotInTheWay(t *testing.T) {
	// A forward or link on another address or port of the same machine is not
	// in the front's way, nor a loopback port's.
	transit := frontedTransit()
	elsewhere := validForward()
	elsewhere.Key, elsewhere.Port, elsewhere.Listen = NewForwardKey(8), 20001, "203.0.113.5"
	transit.Forwards = append(transit.Forwards, elsewhere)
	other := frontForward(9)
	other.Port = 8443
	transit.Forwards = append(transit.Forwards, other)
	if err := ValidateTransit(transit); err != nil {
		t.Fatalf("forwards that do not collide: %v", err)
	}
}

func TestFrontLinkNames(t *testing.T) {
	// A link that is the default may leave names to the default.
	transit := frontedTransit()
	transit.LinksIn[0].Reality.ServerNames = []string{"www.example.com", "www2.example.com"}
	transit.Fronts[0].Routes = transit.Fronts[0].Routes[:2]
	transit.Fronts[0].Listeners = transit.Fronts[0].Listeners[:1]
	transit.Fronts[0].Default = FrontTarget{Link: NewLinkKey(2)}
	if err := ValidateTransit(transit); err != nil {
		t.Fatalf("link as the default: %v", err)
	}
	// Routed by name, every one of its names must reach it.
	transit = frontedTransit()
	transit.LinksIn[0].Reality.ServerNames = []string{"www.example.com", "www2.example.com"}
	transit.Fronts[0].Routes[2].ServerNames = []string{"www.example.com", "www2.example.com"}
	if err := ValidateTransit(transit); err != nil {
		t.Fatalf("link routed by all its names: %v", err)
	}
	transit.Fronts[0].Routes[2].ServerNames = []string{"www.example.com"}
	if err := ValidateTransit(transit); err == nil {
		t.Fatal("a link name nothing routes to the link accepted")
	}
	// Split over two routes is fine.
	transit.Fronts[0].Routes[2].ServerNames = []string{"www.example.com"}
	transit.Fronts[0].Routes = append(transit.Fronts[0].Routes, FrontRoute{
		ServerNames: []string{"www2.example.com"}, Target: FrontTarget{Link: NewLinkKey(2)}})
	if err := ValidateTransit(transit); err != nil {
		t.Fatalf("link names over two routes: %v", err)
	}
}

func TestMappedBindsAreTheirIPv4(t *testing.T) {
	if !bindsOverlap("::ffff:203.0.113.5", "203.0.113.5") || !bindsOverlap("::ffff:127.0.0.1", "0.0.0.0") {
		t.Fatal("a mapped address is not its IPv4 address")
	}
	if bindsOverlap("::ffff:203.0.113.5", "203.0.113.6") {
		t.Fatal("distinct addresses overlap")
	}
	if !bindIncludesLoopback("::ffff:127.0.0.1") || bindIncludesLoopback("::1") || bindIncludesLoopback("203.0.113.5") ||
		!bindIncludesLoopback("") || !bindIncludesLoopback("::") || !bindIncludesLoopback("127.0.0.2") {
		t.Fatal("bindIncludesLoopback")
	}
	transit := &Transit{}
	for id, listen := range map[int64]string{1: "203.0.113.5", 2: "::ffff:203.0.113.5"} {
		transit.Fronts = append(transit.Fronts, Front{
			Key: NewFrontKey(id), Listen: listen, Port: 443,
			Listeners: []FrontedListener{{Listener: NewListenerKey(id), LoopbackPort: 20000 + int(id)}},
			Routes:    []FrontRoute{{ServerNames: []string{"x.example.com"}, Target: FrontTarget{Listener: NewListenerKey(id)}}},
			Default:   FrontTarget{Listener: NewListenerKey(id)},
		})
	}
	if err := ValidateTransit(transit); err == nil {
		t.Fatal("two spellings of one bind accepted as two fronts")
	}
}

func TestTCPProbeOfAFrontRouteForwardIsRefused(t *testing.T) {
	transit := frontedTransit()
	transit.Probe = &ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000,
		Forwards: []ProbeTarget{{Key: NewForwardKey(7), Method: ProbeMethodTCP}}}
	if err := ValidateTransit(transit); err == nil {
		t.Fatal("tcp probe of a forward that is a front route target accepted")
	}
}

func TestExternalOnAnotherHostsBindIsFine(t *testing.T) {
	transit := frontedTransit()
	transit.Fronts[0].Listeners = transit.Fronts[0].Listeners[:1]
	other := validForward()
	other.Key, other.Listen, other.Port = NewForwardKey(8), "203.0.113.5", 8443
	transit.Forwards = append(transit.Forwards, other)
	// The same port on another address, and another port on the same address.
	for _, external := range []FrontExternal{{Host: "203.0.113.9", Port: 8443}, {Host: "203.0.113.5", Port: 8444}} {
		transit.Fronts[0].Default = FrontTarget{External: &external}
		if err := ValidateTransit(transit); err != nil {
			t.Errorf("external %+v: %v", external, err)
		}
	}
}
