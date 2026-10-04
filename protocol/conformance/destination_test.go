package conformance

import (
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"reflect"
	"testing"
)

func TestDestinationMatchVectors(t *testing.T) {
	for _, v := range DestinationMatchVectors {
		t.Run(v.Name, func(t *testing.T) {
			if err := protocol.ValidateDestinationPolicy(v.Policy); err != nil {
				t.Fatal(err)
			}
			got := protocol.MatchDestination(v.Policy, v.Subject, v.Target, v.Port, v.Network)
			if !reflect.DeepEqual(got, v.Want) {
				t.Fatalf("match = %#v, want %#v", got, v.Want)
			}
		})
	}
}
