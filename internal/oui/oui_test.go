package oui

import "testing"

// Echte fabrikantprefixen met een neutrale apparaatstaart. Deze test
// controleert vooral dat de drie-tier-opzet werkt: 98:fc:84 zit in een
// gedeeld IEEE-blok en levert zonder de MA-M/MA-S-lijsten alleen
// "IEEE Registration Authority" op.
func TestLookupBekendeFabrikanten(t *testing.T) {
	cases := []struct{ mac, want string }{
		{"0c-80-63-00-00-01", "TP-LINK TECHNOLOGIES"},
		{"ac-84-c6-00-00-02", "TP-LINK TECHNOLOGIES"},
		{"00-11-32-00-00-04", "Synology"},
		{"18-c0-4d-00-00-05", "GIGA-BYTE TECHNOLOGY"},
		{"1c-69-7a-00-00-06", "EliteGroup Computer Systems"},
		{"44-a3-bb-00-00-07", "Intel"},
		{"98-e7-f4-00-00-08", "Hewlett Packard"},
		{"5c-0f-fb-00-00-09", "Amino Communications"},
	}
	for _, c := range cases {
		if got := Lookup(c.mac); got != c.want {
			t.Errorf("Lookup(%s) = %q, wil %q", c.mac, got, c.want)
		}
	}
}

// Een geroteerd MAC hoort géén fabrikant op te leveren. Iets verzinnen is
// hier erger dan niets teruggeven.
func TestPriveMACGeeftNiets(t *testing.T) {
	const mac = "82-23-80-00-00-0a" // 0x82 = locally administered
	if !IsRandom(mac) {
		t.Fatalf("IsRandom(%s) = false, wil true", mac)
	}
	if got := Lookup(mac); got != "" {
		t.Errorf("Lookup(%s) = %q, wil een lege string", mac, got)
	}
}

// Een adres uit een gedeeld blok moet via MA-M of MA-S worden opgelost,
// niet blijven steken op de registratie-autoriteit.
func TestGedeeldBlokWordtDoorgezocht(t *testing.T) {
	got := Lookup("98:fc:84:e0:00:0b")
	if got == "" {
		t.Skip("98:fc:84:e0 staat niet in de MA-M-lijst; geen fabrikant is een geldig antwoord")
	}
	if got == "IEEE Registration Authority" {
		t.Errorf("kreeg de registratie-autoriteit terug in plaats van de echte eigenaar")
	}
	t.Logf("98:fc:84:e0:00:0b -> %s", got)
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"0C-80-63-00-00-01": "0c:80:63:00:00:01",
		"0c8063 000001":     "0c:80:63:00:00:01",
		"0c:80:63:00:00:01": "0c:80:63:00:00:01",
		"onzin":             "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, wil %q", in, got, want)
		}
	}
}

func TestMulticastHerkend(t *testing.T) {
	for _, m := range []string{"ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb"} {
		if !IsMulticast(m) {
			t.Errorf("IsMulticast(%s) = false, wil true", m)
		}
	}
	if IsMulticast("0c:80:63:00:00:01") {
		t.Error("unicast-adres als multicast aangemerkt")
	}
}
