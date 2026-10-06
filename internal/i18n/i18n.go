// Package i18n houdt de teksten van de app bij, in elke taal die er is.
//
// De catalogus is de enige bron van waarheid en wordt gedeeld met de
// frontend: die haalt hem op via een gebonden methode in plaats van een
// eigen kopie bij te houden. Een taal toevoegen is daardoor één JSON-
// bestand in locales/ zetten — er hoeft geen regel code bij.
//
// De backend zet zelf geen zinnen meer in elkaar. Gebeurtenissen en
// notities dragen een sleutel plus parameters; pas op het scherm wordt er
// een zin van gemaakt. Zo verandert ook het bestaande logboek van taal
// zodra je omschakelt, in plaats van in de oude taal te blijven staan.
package i18n

import (
	"embed"
	"encoding/json"
	"path"
	"sort"
	"strings"
	"sync"
)

//go:embed locales/*.json
var bestanden embed.FS

// Standaard is de taal waarop we terugvallen als er niets gekozen is en
// als een sleutel in een andere taal ontbreekt.
const Standaard = "en"

var (
	eenmalig  sync.Once
	catalogus map[string]map[string]string
)

func laad() {
	catalogus = map[string]map[string]string{}
	items, err := bestanden.ReadDir("locales")
	if err != nil {
		return
	}
	for _, it := range items {
		if it.IsDir() || !strings.HasSuffix(it.Name(), ".json") {
			continue
		}
		ruw, err := bestanden.ReadFile(path.Join("locales", it.Name()))
		if err != nil {
			continue
		}
		var m map[string]string
		if json.Unmarshal(ruw, &m) != nil {
			continue
		}
		catalogus[strings.TrimSuffix(it.Name(), ".json")] = m
	}
}

// Taal beschrijft één beschikbare taal voor de keuzelijst.
type Taal struct {
	Code string `json:"code"`
	Naam string `json:"name"`
}

// Talen geeft alle beschikbare talen, op code gesorteerd.
func Talen() []Taal {
	eenmalig.Do(laad)
	uit := make([]Taal, 0, len(catalogus))
	for code, m := range catalogus {
		naam := m["lang.name"]
		if naam == "" {
			naam = code
		}
		uit = append(uit, Taal{Code: code, Naam: naam})
	}
	sort.Slice(uit, func(a, b int) bool { return uit[a].Code < uit[b].Code })
	return uit
}

// Bestaat zegt of we deze taal kennen.
func Bestaat(code string) bool {
	eenmalig.Do(laad)
	_, ok := catalogus[code]
	return ok
}

// Catalogus geeft alle teksten van één taal, aangevuld met de standaard-
// taal voor sleutels die nog niet vertaald zijn. Zo levert een halve
// vertaling nooit lege knoppen op.
func Catalogus(code string) map[string]string {
	eenmalig.Do(laad)
	uit := map[string]string{}
	for k, v := range catalogus[Standaard] {
		uit[k] = v
	}
	if code != Standaard {
		for k, v := range catalogus[code] {
			uit[k] = v
		}
	}
	return uit
}

// T vertaalt één sleutel en vult de parameters in.
//
// Bedoeld voor de plekken waar de backend zelf tekst moet tonen: de CLI,
// en foutmeldingen die als gewone Go-error naar buiten gaan. De frontend
// vertaalt zelf, met dezelfde catalogus.
func T(code, sleutel string, args ...string) string {
	eenmalig.Do(laad)

	tekst, ok := catalogus[code][sleutel]
	if !ok {
		tekst, ok = catalogus[Standaard][sleutel]
	}
	if !ok {
		// Een onbekende sleutel tonen we als zichzelf. Dat valt op tijdens
		// het bouwen zonder de app onbruikbaar te maken.
		return sleutel
	}
	return Vul(tekst, args...)
}

// Vul vervangt {naam}-plaatshouders. args komt in paren: naam, waarde.
func Vul(tekst string, args ...string) string {
	for i := 0; i+1 < len(args); i += 2 {
		tekst = strings.ReplaceAll(tekst, "{"+args[i]+"}", args[i+1])
	}
	return tekst
}
