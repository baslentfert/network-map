package i18n

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Elke taal moet exact dezelfde sleutels hebben. Een vergeten vertaling
// valt anders pas op als iemand de app in die taal opent en een lege knop
// ziet — dit maakt er een bouwfout van.
func TestAlleTalenZelfdeSleutels(t *testing.T) {
	talen := Talen()
	if len(talen) < 2 {
		t.Skip("minder dan twee talen; niets te vergelijken")
	}

	basis := Catalogus(Standaard)
	for _, taal := range talen {
		if taal.Code == Standaard {
			continue
		}
		eenmalig.Do(laad)
		ruw := catalogus[taal.Code]

		var ontbreekt, teveel []string
		for k := range basis {
			if _, ok := ruw[k]; !ok {
				ontbreekt = append(ontbreekt, k)
			}
		}
		for k := range ruw {
			if _, ok := basis[k]; !ok {
				teveel = append(teveel, k)
			}
		}
		sort.Strings(ontbreekt)
		sort.Strings(teveel)

		if len(ontbreekt) > 0 {
			t.Errorf("%s mist %d sleutels: %s", taal.Code, len(ontbreekt), strings.Join(ontbreekt, ", "))
		}
		if len(teveel) > 0 {
			t.Errorf("%s heeft sleutels die %s niet kent: %s", taal.Code, Standaard, strings.Join(teveel, ", "))
		}
	}
}

var plaatshouder = regexp.MustCompile(`\{([a-zA-Z]+)\}`)

// Een vertaling mag geen plaatshouder toevoegen of laten vallen: dan komt
// er straks een letterlijke {name} op het scherm, of verdwijnt er juist
// informatie uit een melding.
func TestPlaatshoudersKomenOvereen(t *testing.T) {
	eenmalig.Do(laad)
	basis := catalogus[Standaard]

	for _, taal := range Talen() {
		if taal.Code == Standaard {
			continue
		}
		for sleutel, vertaling := range catalogus[taal.Code] {
			origineel, ok := basis[sleutel]
			if !ok {
				continue
			}
			a := plaatshoudersIn(origineel)
			b := plaatshoudersIn(vertaling)
			if strings.Join(a, ",") != strings.Join(b, ",") {
				t.Errorf("%s: plaatshouders verschillen in %q\n  %s: %v\n  %s: %v",
					taal.Code, sleutel, Standaard, a, taal.Code, b)
			}
		}
	}
}

func plaatshoudersIn(s string) []string {
	var uit []string
	for _, m := range plaatshouder.FindAllStringSubmatch(s, -1) {
		uit = append(uit, m[1])
	}
	sort.Strings(uit)
	return uit
}

func TestVulVervangtParameters(t *testing.T) {
	got := Vul("{name} kreeg {ip} (was {old})", "name", "NAS", "ip", "1.2.3.4", "old", "1.2.3.9")
	wil := "NAS kreeg 1.2.3.4 (was 1.2.3.9)"
	if got != wil {
		t.Errorf("Vul = %q, wil %q", got, wil)
	}
}

// Een onbekende sleutel mag de app niet stukmaken, maar moet wel opvallen.
func TestOnbekendeSleutelValtOp(t *testing.T) {
	if got := T(Standaard, "dit.bestaat.niet"); got != "dit.bestaat.niet" {
		t.Errorf("T = %q, wil de sleutel zelf terug", got)
	}
}

// Een taal die we niet kennen valt terug op de standaardtaal in plaats van
// lege teksten op te leveren.
func TestOnbekendeTaalValtTerug(t *testing.T) {
	got := T("klingon", "app.title")
	wil := T(Standaard, "app.title")
	if got != wil {
		t.Errorf("T = %q, wil terugval op %q", got, wil)
	}
}

// Het inhoudelijke punt van deze opzet: één en dezelfde gebeurtenis komt
// er in elke taal anders uit, zonder dat de backend iets anders opslaat.
// Daardoor verandert ook een logboek dat er al staat mee bij het wisselen.
func TestZelfdeGebeurtenisInBeideTalen(t *testing.T) {
	args := []string{"name", "FileServer", "ip", "192.168.0.100", "old", "192.168.0.42"}

	nl := T("nl", "ev.newAddress", args...)
	en := T("en", "ev.newAddress", args...)

	if nl == en {
		t.Fatalf("beide talen leverden dezelfde zin op: %q", nl)
	}
	for _, zin := range []string{nl, en} {
		for _, deel := range []string{"FileServer", "192.168.0.100", "192.168.0.42"} {
			if !strings.Contains(zin, deel) {
				t.Errorf("%q mist %q", zin, deel)
			}
		}
		if strings.Contains(zin, "{") {
			t.Errorf("%q heeft een niet-ingevulde plaatshouder", zin)
		}
	}
	t.Logf("nl: %s", nl)
	t.Logf("en: %s", en)
}
