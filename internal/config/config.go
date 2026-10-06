// Package config bewaart de keuzes van de gebruiker tussen sessies:
// de taal en de zelf toegekende apparaatnamen.
//
// Het pad is instelbaar zodat tests niet in de echte configuratiemap van
// de gebruiker schrijven.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const mapNaam = "netwerksniffer"

var (
	mu      sync.RWMutex
	basis   string
	gezocht bool
)

// ZetMap wijst een andere map aan. Bedoeld voor tests; laat leeg om de
// standaard configuratiemap van het besturingssysteem te gebruiken.
func ZetMap(pad string) {
	mu.Lock()
	basis, gezocht = pad, true
	mu.Unlock()
}

func dir() string {
	mu.RLock()
	if gezocht {
		defer mu.RUnlock()
		return basis
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()
	if !gezocht {
		d, err := os.UserConfigDir()
		if err == nil {
			basis = filepath.Join(d, mapNaam)
		}
		gezocht = true
	}
	return basis
}

func pad(bestand string) string {
	d := dir()
	if d == "" {
		return ""
	}
	return filepath.Join(d, bestand)
}

func schrijf(bestand string, inhoud []byte) error {
	p := pad(bestand)
	if p == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, inhoud, 0o644)
}

// LaadTaal geeft de bewaarde taalcode, of een lege string als er nog geen
// keuze is gemaakt. De aanroeper bepaalt waar hij dan op terugvalt.
func LaadTaal() string {
	p := pad("taal.txt")
	if p == "" {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// BewaarTaal legt de keuze vast voor de volgende keer.
func BewaarTaal(code string) error {
	return schrijf("taal.txt", []byte(code))
}

// LaadJSON leest een bewaard bestand in doel. Ontbreekt het of is het
// onleesbaar, dan blijft doel zoals het was — de app hoort dan gewoon met
// een lege basislijn te beginnen in plaats van te weigeren te starten.
func LaadJSON(bestand string, doel any) error {
	p := pad(bestand)
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, doel)
}

// BewaarJSON schrijft een waarde weg.
func BewaarJSON(bestand string, waarde any) error {
	b, err := json.MarshalIndent(waarde, "", "  ")
	if err != nil {
		return err
	}
	return schrijf(bestand, b)
}

// LaadNamen geeft de zelf toegekende apparaatnamen, op MAC-adres.
func LaadNamen() map[string]string {
	p := pad("namen.json")
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

// BewaarNamen schrijft de zelf toegekende namen weg.
//
// Een lege verzameling wordt ook opgeslagen: als je de laatste naam wist,
// moet die na een herstart weg blijven en niet terugkomen.
func BewaarNamen(m map[string]string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return schrijf("namen.json", b)
}
