package store

import (
	"testing"

	"netwerksniffer/internal/model"
)

func hostOp(s *Store, ip string) *model.Host {
	for _, h := range s.Graph().Hosts {
		if h.IP == ip {
			c := h
			return &c
		}
	}
	return nil
}

// De ping-sweep vindt een host op z'n IP; pas daarna levert de ARP-cache
// het MAC-adres. Dat moet één host worden, niet twee.
func TestPingDanARPWordtEenHost(t *testing.T) {
	s := New(nil)
	s.Observe(Fact{IP: "192.168.0.50", TTL: 64})
	s.Observe(Fact{IP: "192.168.0.50", MAC: "00:11:32:00:00:04", Origin: model.OriginARP})

	hosts := s.Graph().Hosts
	if len(hosts) != 1 {
		t.Fatalf("kreeg %d hosts, wil er 1: %+v", len(hosts), hosts)
	}
	h := hosts[0]
	if h.MAC != "00:11:32:00:00:04" {
		t.Errorf("MAC = %q, wil 00:11:32:00:00:04", h.MAC)
	}
	if h.TTL != 64 {
		t.Errorf("TTL uit de ping-sweep is verloren gegaan bij het samenvoegen")
	}
	if h.Key != h.MAC {
		t.Errorf("Key = %q, wil de MAC als stabiele sleutel", h.Key)
	}
}

// Twee verschillende MAC-adressen op hetzelfde IP zijn twee apparaten,
// geen dubbele registratie. Ze samenvoegen liet eerder één van beide z'n
// MAC verliezen en gaf de ander een adres dat niet van hem was.
func TestZelfdeIPTweeMACsBlijftTweeHosts(t *testing.T) {
	s := New(nil)
	s.Observe(Fact{IP: "192.168.0.110", MAC: "82:23:80:00:00:0a", Origin: model.OriginARP})
	s.Observe(Fact{IP: "192.168.0.110", MAC: "98:fc:84:e0:00:0b", Origin: "netbios", Name: "IETS"})

	hosts := s.Graph().Hosts
	if len(hosts) != 2 {
		t.Fatalf("kreeg %d hosts, wil er 2 — verschillende MAC's zijn verschillende apparaten", len(hosts))
	}
	for _, h := range hosts {
		if h.MAC == "" {
			t.Errorf("host %s is z'n MAC kwijtgeraakt bij het verwerken", h.Key)
		}
	}
}

// De naam die een mens koos verslaat elke automatisch gevonden naam, maar
// de gevonden namen blijven zichtbaar met hun herkomst.
func TestEigenNaamWintEnBronnenBlijven(t *testing.T) {
	s := New(nil)
	s.Observe(Fact{IP: "192.168.0.100", MAC: "00:11:32:00:00:04", Origin: model.OriginARP})
	s.Observe(Fact{IP: "192.168.0.100", Name: "FILESERVER", Origin: model.OriginNetBIOS})
	s.Observe(Fact{IP: "192.168.0.100", Name: "DiskStation.local", Origin: model.OriginMDNS})

	h := hostOp(s, "192.168.0.100")
	if h == nil {
		t.Fatal("host niet gevonden")
	}
	// mDNS staat hoger dan NetBIOS in de rangorde.
	if h.Name != "DiskStation.local" {
		t.Errorf("Name = %q, wil DiskStation.local (mDNS verslaat NetBIOS)", h.Name)
	}

	s.SetAlias(h.Key, "NAS zolder")
	h = hostOp(s, "192.168.0.100")
	if h.Name != "NAS zolder" {
		t.Errorf("Name = %q, wil de eigen naam", h.Name)
	}
	if len(h.Names) != 3 {
		t.Errorf("kreeg %d naambronnen, wil er 3 — gevonden namen horen bewaard te blijven", len(h.Names))
	}
}

// Een tweede MAC dat een bestaand IP claimt is het patroon van
// ARP-spoofing. We kiezen geen kant, maar het moet wel gemeld worden.
func TestARPConflictGeeftWaarschuwing(t *testing.T) {
	s := New(nil)
	s.Observe(Fact{IP: "192.168.0.1", MAC: "0c:80:63:00:00:01", Origin: model.OriginARP})
	s.Observe(Fact{IP: "192.168.0.1", MAC: "98:e7:f4:00:00:08", Origin: model.OriginARP})

	var gemeld bool
	for _, e := range s.Events() {
		if e.Tag == model.TagAlert {
			gemeld = true
		}
	}
	if !gemeld {
		t.Error("geen waarschuwing in het logboek na een dubbele IP-claim")
	}
}
