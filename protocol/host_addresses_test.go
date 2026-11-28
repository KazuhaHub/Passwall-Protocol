package protocol

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func hostSampleWithAddresses(addresses ...string) HostObservation {
	sample := hostSample()
	sample.Network.Interfaces[0].Addresses = addresses
	return sample
}

func TestInterfaceAddressesAcceptConformingLists(t *testing.T) {
	for name, addresses := range map[string][]string{
		"none":               nil,
		"public and private": {"10.0.0.5/8", "203.0.113.7/24", "2001:db8::1/64", "fd00::5/64"},
		"host bits kept":     {"192.168.1.20/24"},
		"single host":        {"198.51.100.1/32", "2001:db8::2/128"},
		"ipv4 link-local":    {"169.254.10.1/16"},
		"cgnat":              {"100.64.0.9/10"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateHostObservation(hostSampleWithAddresses(addresses...)); err != nil {
				t.Fatalf("conforming addresses rejected: %v", err)
			}
		})
	}
}

func TestInterfaceAddressesRejectMalformedLists(t *testing.T) {
	cases := map[string]struct {
		addresses []string
		want      string
	}{
		"bare address":       {[]string{"203.0.113.7"}, "canonical"},
		"non-canonical ipv6": {[]string{"2001:0db8::1/64"}, "canonical"},
		"zone":               {[]string{"fe80::1%eth0/64"}, "canonical"},
		"ipv4-mapped":        {[]string{"::ffff:203.0.113.7/120"}, "IPv4-mapped"},
		"ipv6 link-local":    {[]string{"fe80::1/64"}, "link-local"},
		"loopback":           {[]string{"127.0.0.1/8"}, "unicast"},
		"multicast":          {[]string{"224.0.0.1/32"}, "unicast"},
		"unspecified":        {[]string{"0.0.0.0/0"}, "unicast"},
		"broadcast":          {[]string{"255.255.255.255/32"}, "broadcast"},
		"prefix too long":    {[]string{"203.0.113.7/33"}, "canonical"},
		"empty":              {[]string{""}, "length"},
		"oversized":          {[]string{strings.Repeat("1", MaxInterfaceAddressBytes+1)}, "length"},
		"unsorted":           {[]string{"203.0.113.7/24", "10.0.0.5/8"}, "sorted"},
		"ipv6 before ipv4":   {[]string{"2001:db8::1/64", "10.0.0.5/8"}, "sorted"},
		"same address twice": {[]string{"10.0.0.5/8", "10.0.0.5/24"}, "repeats"},
		"too many on one":    {manyAddresses(MaxAddressesPerInterface + 1), "at most"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidateHostObservation(hostSampleWithAddresses(testCase.addresses...))
			if err == nil {
				t.Fatal("malformed addresses accepted")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error %q does not mention %q", err, testCase.want)
			}
		})
	}
}

func manyAddresses(count int) []string {
	addresses := make([]string, count)
	for index := range addresses {
		addresses[index] = fmt.Sprintf("10.0.%d.%d/16", index/250, index%250+1)
	}
	return addresses
}

func TestInterfaceAddressesBoundTheWholeObservation(t *testing.T) {
	sample := hostSample()
	template := sample.Network.Interfaces[0]
	sample.Network.Interfaces = nil
	perInterface := MaxAddressesPerInterface
	count := MaxNetworkAddresses/perInterface + 1
	for index := 0; index < count; index++ {
		networkInterface := template
		networkInterface.Name = fmt.Sprintf("eth%d", index)
		networkInterface.Index = index + 2
		networkInterface.Addresses = manyAddresses(perInterface)
		sample.Network.Interfaces = append(sample.Network.Interfaces, networkInterface)
	}
	err := ValidateHostObservation(sample)
	if err == nil || !strings.Contains(err.Error(), "interface addresses") {
		t.Fatalf("observation over MaxNetworkAddresses: %v", err)
	}
	sample.Network.Interfaces = sample.Network.Interfaces[:count-1]
	if err := ValidateHostObservation(sample); err != nil {
		t.Fatalf("observation at MaxNetworkAddresses rejected: %v", err)
	}
	body, err := json.Marshal(sample)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > MaxHostObservationBytes/2 {
		t.Fatalf("a full address list takes %d of %d host bytes", len(body), MaxHostObservationBytes)
	}
}

func TestValidateNodeReportTiesInterfaceAddressesToTheirCapability(t *testing.T) {
	report := NodeReport{
		AgentID: "agent-1", Have: emptyHave(),
		Capabilities: []string{CapabilityHostTelemetry},
		Host:         hostPtr(hostSampleWithAddresses("10.0.0.5/8")),
	}
	if err := ValidateNodeReport(report); err == nil || !strings.Contains(err.Error(), CapabilityHostInterfaceAddresses) {
		t.Fatalf("addresses without the capability: %v", err)
	}
	report.Capabilities = append(report.Capabilities, CapabilityHostInterfaceAddresses)
	if err := ValidateNodeReport(report); err != nil {
		t.Fatalf("addresses with the capability rejected: %v", err)
	}
	// The capability with no address anywhere is a host whose links carry none.
	report.Host = hostPtr(hostSample())
	if err := ValidateNodeReport(report); err != nil {
		t.Fatalf("capability without addresses rejected: %v", err)
	}
}

func TestInterfaceAddressesAreOmittedWhenEmpty(t *testing.T) {
	body, err := json.Marshal(hostSample().Network.Interfaces[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"addresses"`) {
		t.Fatalf("an interface without addresses must encode as before: %s", body)
	}
}
