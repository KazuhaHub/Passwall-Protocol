package conformance

// FrontVector is one serialised protocol.Transit and whether it is acceptable,
// held to ValidateTransit by the path ProbeVector describes. The expected
// values are written from the rules, not copied from the code; append, never
// edit a verdict to make an implementation pass.
type FrontVector = ProbeVector

const (
	frontForwardJSON = `{"key":"fwd_7","port":443,"target":"landing.example.com","target_port":443,"network":"tcp"}`
	frontLinkJSON    = `{"key":"lnk_2","port":443,"protocol":"vless_reality","reality":{"uuid":"0f62f495-b5ca-4509-b6cd-54a040deafd5","private_key":"sCg4m4EzwI-ABTXkpBUlq7bXjvoGzOubGY3J8dhTL2o","target":"www.example.com:443","server_names":["www.example.com"],"short_ids":["","a1b2"]}}`
	frontListeners   = `"listeners":[{"listener":"lst_1","loopback_port":20001},{"listener":"lst_2","loopback_port":20002}]`
	frontRouteA      = `{"server_names":["a.example.com"],"target":{"listener":"lst_1"}}`
	frontDefault     = `"default":{"listener":"lst_2"}`
)

func front(body string) string { return `{"fronts":[{"key":"fnt_1","port":443,` + body + `}]}` }

func frontWith(prefix, body string) string {
	return `{` + prefix + `"fronts":[{"key":"fnt_1","port":443,` + body + `}]}`
}

// FrontTransitVectors is the shared table for Transit.Fronts.
var FrontTransitVectors = []FrontVector{
	{Name: "listeners behind one front", Valid: true,
		JSON: front(frontListeners + `,"routes":[` + frontRouteA + `],` + frontDefault)},
	{Name: "every kind of target", Valid: true,
		JSON: frontWith(`"forwards":[`+frontForwardJSON+`],"links_in":[`+frontLinkJSON+`],`,
			frontListeners+`,"routes":[`+frontRouteA+`,{"server_names":["b.example.com","c.example.com"],"target":{"forward":"fwd_7"}},{"server_names":["www.example.com"],"target":{"link":"lnk_2"}}],`+frontDefault)},
	{Name: "external default", Valid: true,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"www.example.org","port":443}}`)},
	{Name: "external default on another port of loopback", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"127.0.0.1","port":8080}}`)},
	{Name: "a listener that is a route target and the default", Valid: true,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}`)},
	{Name: "two fronts on distinct addresses of one port", Valid: true,
		JSON: `{"fronts":[` +
			`{"key":"fnt_1","listen":"203.0.113.5","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}},` +
			`{"key":"fnt_2","listen":"203.0.113.6","port":443,"listeners":[{"listener":"lst_2","loopback_port":20002}],"routes":[{"server_names":["b.example.com"],"target":{"listener":"lst_2"}}],"default":{"listener":"lst_2"}}]}`},
	{Name: "two fronts on distinct ports", Valid: true,
		JSON: `{"fronts":[` +
			`{"key":"fnt_1","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}},` +
			`{"key":"fnt_2","port":8443,"listeners":[{"listener":"lst_2","loopback_port":20002}],"routes":[{"server_names":["b.example.com"],"target":{"listener":"lst_2"}}],"default":{"listener":"lst_2"}}]}`},
	{Name: "two fronts on one bind", Valid: false,
		JSON: `{"fronts":[` +
			`{"key":"fnt_1","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}},` +
			`{"key":"fnt_2","port":443,"listeners":[{"listener":"lst_2","loopback_port":20002}],"routes":[{"server_names":["b.example.com"],"target":{"listener":"lst_2"}}],"default":{"listener":"lst_2"}}]}`},
	{Name: "a wildcard front over a specific address", Valid: false,
		JSON: `{"fronts":[` +
			`{"key":"fnt_1","listen":"203.0.113.5","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}},` +
			`{"key":"fnt_2","port":443,"listeners":[{"listener":"lst_2","loopback_port":20002}],"routes":[{"server_names":["b.example.com"],"target":{"listener":"lst_2"}}],"default":{"listener":"lst_2"}}]}`},
	{Name: "the same front key twice", Valid: false,
		JSON: `{"fronts":[` +
			`{"key":"fnt_1","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}},` +
			`{"key":"fnt_1","port":8443,"listeners":[{"listener":"lst_2","loopback_port":20002}],"routes":[{"server_names":["b.example.com"],"target":{"listener":"lst_2"}}],"default":{"listener":"lst_2"}}]}`},
	{Name: "a listener behind two fronts", Valid: false,
		JSON: `{"fronts":[` +
			`{"key":"fnt_1","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}},` +
			`{"key":"fnt_2","port":8443,"listeners":[{"listener":"lst_1","loopback_port":20002}],"routes":[{"server_names":["b.example.com"],"target":{"listener":"lst_1"}}],"default":{"listener":"lst_1"}}]}`},
	{Name: "front key of a forward", Valid: false,
		JSON: `{"fronts":[{"key":"fwd_1","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}}]}`},
	{Name: "front key with a leading zero", Valid: false,
		JSON: `{"fronts":[{"key":"fnt_01","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}}]}`},
	{Name: "port zero", Valid: false,
		JSON: `{"fronts":[{"key":"fnt_1","port":0,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}}]}`},
	{Name: "default omitted", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `]`)},
	{Name: "default names two targets", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1","external":{"host":"www.example.org","port":443}}`)},
	{Name: "no routes", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[],"default":{"listener":"lst_1"}`)},
	{Name: "route with no names", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[{"server_names":[],"target":{"listener":"lst_1"}}],"default":{"listener":"lst_1"}`)},
	{Name: "names out of order", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[{"server_names":["b.example.com","a.example.com"],"target":{"listener":"lst_1"}}],"default":{"listener":"lst_1"}`)},
	{Name: "name in two routes of one front", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001},{"listener":"lst_2","loopback_port":20002}],"routes":[` + frontRouteA + `,{"server_names":["a.example.com"],"target":{"listener":"lst_2"}}],"default":{"listener":"lst_2"}`)},
	{Name: "uppercase name", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[{"server_names":["A.example.com"],"target":{"listener":"lst_1"}}],"default":{"listener":"lst_1"}`)},
	{Name: "wildcard name", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[{"server_names":["*.example.com"],"target":{"listener":"lst_1"}}],"default":{"listener":"lst_1"}`)},
	{Name: "address as a name", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[{"server_names":["203.0.113.1"],"target":{"listener":"lst_1"}}],"default":{"listener":"lst_1"}`)},
	{Name: "listener target that is not fronted", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[{"server_names":["a.example.com"],"target":{"listener":"lst_9"}}],"default":{"listener":"lst_1"}`)},
	{Name: "fronted listener that nothing routes to", Valid: false,
		JSON: front(frontListeners + `,"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}`)},
	{Name: "loopback port zero", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":0}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}`)},
	{Name: "loopback port repeated", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001},{"listener":"lst_2","loopback_port":20001}],"routes":[` + frontRouteA + `],` + frontDefault)},
	{Name: "forward on another port", Valid: false,
		JSON: frontWith(`"forwards":[{"key":"fwd_7","port":444,"target":"landing.example.com","target_port":443,"network":"tcp"}],`,
			`"routes":[{"server_names":["a.example.com"],"target":{"forward":"fwd_7"}}],"default":{"external":{"host":"www.example.org","port":443}}`)},
	{Name: "forward that also relays udp", Valid: false,
		JSON: frontWith(`"forwards":[{"key":"fwd_7","port":443,"target":"landing.example.com","target_port":443,"network":"tcp,udp"}],`,
			`"routes":[{"server_names":["a.example.com"],"target":{"forward":"fwd_7"}}],"default":{"external":{"host":"www.example.org","port":443}}`)},
	{Name: "forward that is not in the transit", Valid: false,
		JSON: front(`"routes":[{"server_names":["a.example.com"],"target":{"forward":"fwd_7"}}],"default":{"external":{"host":"www.example.org","port":443}}`)},
	{Name: "link that is ss2022", Valid: false,
		JSON: frontWith(`"links_in":[{"key":"lnk_2","port":443,"protocol":"ss2022","ss":{"method":"2022-blake3-aes-128-gcm","password":"glwKkLUrNxQ4VbjbZG4svg=="}}],`,
			`"routes":[{"server_names":["a.example.com"],"target":{"link":"lnk_2"}}],"default":{"external":{"host":"www.example.org","port":443}}`)},
	{Name: "link route naming a name the link does not serve", Valid: false,
		JSON: frontWith(`"links_in":[`+frontLinkJSON+`],`,
			`"routes":[{"server_names":["d.example.com"],"target":{"link":"lnk_2"}}],"default":{"external":{"host":"www.example.org","port":443}}`)},
	{Name: "link as the default with its name routed to a listener", Valid: false,
		JSON: frontWith(`"links_in":[`+frontLinkJSON+`],`,
			`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[{"server_names":["www.example.com"],"target":{"listener":"lst_1"}}],"default":{"link":"lnk_2"}`)},
	{Name: "link as the default and a route target", Valid: true,
		JSON: frontWith(`"links_in":[`+frontLinkJSON+`],`,
			`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[`+frontRouteA+`,{"server_names":["www.example.com"],"target":{"link":"lnk_2"}}],"default":{"link":"lnk_2"}`)},
	{Name: "forward on the front's bind that is not a target", Valid: false,
		JSON: frontWith(`"forwards":[`+frontForwardJSON+`],`,
			`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[`+frontRouteA+`],"default":{"listener":"lst_1"}`)},
	{Name: "loopback port that a forward on every address holds", Valid: false,
		JSON: frontWith(`"forwards":[{"key":"fwd_7","port":20001,"target":"landing.example.com","target_port":443,"network":"tcp"}],`,
			`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[`+frontRouteA+`],"default":{"listener":"lst_1"}`)},
	{Name: "loopback port that a forward on another address holds", Valid: true,
		JSON: frontWith(`"forwards":[{"key":"fwd_7","listen":"203.0.113.5","port":20001,"target":"landing.example.com","target_port":443,"network":"tcp"}],`,
			`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[`+frontRouteA+`],"default":{"listener":"lst_1"}`)},
	{Name: "external default that is another front's bind", Valid: false,
		JSON: `{"fronts":[` +
			`{"key":"fnt_1","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"203.0.113.5","port":8443}}},` +
			`{"key":"fnt_2","listen":"203.0.113.5","port":8443,"listeners":[{"listener":"lst_2","loopback_port":20002}],"routes":[{"server_names":["b.example.com"],"target":{"listener":"lst_2"}}],"default":{"listener":"lst_2"}}]}`},
	{Name: "external default that is a forward's bind, looping back to the front", Valid: false,
		JSON: `{"forwards":[{"key":"fwd_8","listen":"203.0.113.5","port":8443,"target":"203.0.113.5","target_port":443,"network":"tcp"}],` +
			`"fronts":[{"key":"fnt_1","listen":"203.0.113.5","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"203.0.113.5","port":8443}}}]}`},
	{Name: "external default that is a link's bind", Valid: false,
		JSON: `{"links_in":[{"key":"lnk_5","listen":"203.0.113.9","port":8443,"protocol":"ss2022","ss":{"method":"2022-blake3-aes-128-gcm","password":"glwKkLUrNxQ4VbjbZG4svg=="}}],` +
			`"fronts":[{"key":"fnt_1","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"203.0.113.9","port":8443}}}]}`},
	{Name: "external default on a forward's port at another address", Valid: true,
		JSON: `{"forwards":[{"key":"fwd_8","listen":"203.0.113.5","port":8443,"target":"203.0.113.5","target_port":443,"network":"tcp"}],` +
			`"fronts":[{"key":"fnt_1","listen":"203.0.113.5","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"203.0.113.9","port":8443}}}]}`},
	{Name: "external default in 0.0.0.0/8", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"0.1.2.3","port":8080}}`)},
	{Name: "external default of localhost", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"localhost","port":8080}}`)},
	{Name: "two fronts on spellings of one bind", Valid: false,
		JSON: `{"fronts":[` +
			`{"key":"fnt_1","listen":"203.0.113.5","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}},` +
			`{"key":"fnt_2","listen":"::ffff:203.0.113.5","port":443,"listeners":[{"listener":"lst_2","loopback_port":20002}],"routes":[{"server_names":["b.example.com"],"target":{"listener":"lst_2"}}],"default":{"listener":"lst_2"}}]}`},
	{Name: "tcp probe of a front route forward", Valid: false,
		JSON: frontWith(`"forwards":[`+frontForwardJSON+`],"probe":{"interval_seconds":60,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"tcp"}]},`,
			`"routes":[{"server_names":["a.example.com"],"target":{"forward":"fwd_7"}}],"default":{"external":{"host":"www.example.org","port":443}}`)},
	{Name: "link on another port", Valid: false,
		JSON: frontWith(`"links_in":[`+`{"key":"lnk_2","port":30443,"protocol":"vless_reality","reality":{"uuid":"0f62f495-b5ca-4509-b6cd-54a040deafd5","private_key":"sCg4m4EzwI-ABTXkpBUlq7bXjvoGzOubGY3J8dhTL2o","target":"www.example.com:443","server_names":["www.example.com"],"short_ids":["a1b2"]}}`+`],`,
			`"routes":[{"server_names":["a.example.com"],"target":{"link":"lnk_2"}}],"default":{"external":{"host":"www.example.org","port":443}}`)},
	{Name: "external in a route", Valid: false,
		JSON: front(`"routes":[{"server_names":["a.example.com"],"target":{"external":{"host":"www.example.org","port":443}}}],"default":{"external":{"host":"www.example.org","port":443}}`)},
	{Name: "external host with a port", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"www.example.org:443","port":443}}`)},
	{Name: "external host in capitals", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"WWW.example.org","port":443}}`)},
	{Name: "external port zero", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"www.example.org","port":0}}`)},
	{Name: "external that loops to loopback", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"127.0.0.1","port":443}}`)},
	{Name: "external that loops to the unspecified address", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"::","port":443}}`)},
	{Name: "external that loops to the listen address", Valid: false,
		JSON: `{"fronts":[{"key":"fnt_1","listen":"203.0.113.5","port":443,"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[` + frontRouteA + `],"default":{"external":{"host":"203.0.113.5","port":443}}}]}`},
	{Name: "a loopback port that is the front's own port", Valid: false,
		JSON: front(`"listeners":[{"listener":"lst_1","loopback_port":443}],"routes":[` + frontRouteA + `],"default":{"listener":"lst_1"}`)},
	{Name: "tls probe of a front route forward", Valid: true,
		JSON: frontWith(`"forwards":[`+frontForwardJSON+`],"probe":{"interval_seconds":60,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"tls"}]},`,
			`"routes":[{"server_names":["a.example.com"],"target":{"forward":"fwd_7"}}],"default":{"external":{"host":"www.example.org","port":443}}`)},
	{Name: "tls probe of a forward behind no front", Valid: false,
		JSON: `{"forwards":[` + probeForward + `],"probe":{"interval_seconds":60,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"tls"}]}}`},
	{Name: "tls probe of a forward that is only a front default", Valid: false,
		JSON: frontWith(`"forwards":[`+frontForwardJSON+`],"probe":{"interval_seconds":60,"timeout_ms":3000,"forwards":[{"key":"fwd_7","method":"tls"}]},`,
			`"listeners":[{"listener":"lst_1","loopback_port":20001}],"routes":[`+frontRouteA+`],"default":{"forward":"fwd_7"}`)},
}
