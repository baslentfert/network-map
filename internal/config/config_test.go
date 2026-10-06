package config

import (
	"path/filepath"
	"testing"
)

func tijdelijk(t *testing.T) {
	t.Helper()
	ZetMap(filepath.Join(t.TempDir(), "netwerksniffer"))
	t.Cleanup(func() { ZetMap("") })
}

// De taalkeuze moet een herstart overleven — dat is de hele belofte.
func TestTaalOverleeftHerstart(t *testing.T) {
	tijdelijk(t)

	if got := LaadTaal(); got != "" {
		t.Fatalf("verse installatie gaf %q, wil een lege string", got)
	}
	if err := BewaarTaal("nl"); err != nil {
		t.Fatalf("bewaren mislukt: %v", err)
	}
	if got := LaadTaal(); got != "nl" {
		t.Errorf("LaadTaal = %q, wil nl", got)
	}

	// Overschrijven moet de oude waarde echt vervangen.
	if err := BewaarTaal("en"); err != nil {
		t.Fatalf("bewaren mislukt: %v", err)
	}
	if got := LaadTaal(); got != "en" {
		t.Errorf("na wisselen LaadTaal = %q, wil en", got)
	}
}

func TestNamenOverlevenHerstart(t *testing.T) {
	tijdelijk(t)

	namen := map[string]string{
		"ac:84:c6:00:00:02": "Living room AP",
		"ac:84:c6:00:00:03": "Attic AP",
	}
	if err := BewaarNamen(namen); err != nil {
		t.Fatalf("bewaren mislukt: %v", err)
	}
	terug := LaadNamen()
	if len(terug) != len(namen) {
		t.Fatalf("kreeg %d namen terug, wil er %d", len(terug), len(namen))
	}
	for k, v := range namen {
		if terug[k] != v {
			t.Errorf("%s = %q, wil %q", k, terug[k], v)
		}
	}
}

// Wie de laatste naam wist, wil hem na een herstart niet terugzien.
func TestLaatsteNaamWissenBlijftGewist(t *testing.T) {
	tijdelijk(t)

	BewaarNamen(map[string]string{"aa:bb:cc:dd:ee:ff": "Testkastje"})
	if len(LaadNamen()) != 1 {
		t.Fatal("naam niet bewaard")
	}
	if err := BewaarNamen(map[string]string{}); err != nil {
		t.Fatalf("legen mislukt: %v", err)
	}
	if n := len(LaadNamen()); n != 0 {
		t.Errorf("na wissen nog %d namen; die horen weg te blijven", n)
	}
}

// Zonder schrijfbare map mag er niets omvallen; de app hoort dan gewoon
// zonder bewaarde voorkeuren te draaien.
func TestGeenMapGeeftGeenPaniek(t *testing.T) {
	ZetMap("")
	t.Cleanup(func() { ZetMap("") })
	// Niet in de echte map van de gebruiker schrijven tijdens de test:
	// alleen lezen, en dat mag nooit een panic geven.
	_ = LaadTaal()
	_ = LaadNamen()
}
