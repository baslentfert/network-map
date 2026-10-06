package dnsproxy

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Teller vat samen hoe vaak één apparaat één domein opvroeg.
//
// De losse vragen zijn het ruwe materiaal, maar niemand leest tienduizend
// regels. Wat je wilt zien is "deze camera vroeg dit domein 211 keer op in
// tien minuten" — dat valt op, en één losse regel niet.
type Teller struct {
	Client string    `json:"client"`
	Name   string    `json:"name"`
	Count  int       `json:"count"`
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
	// Adressen zijn de IP's waar dit domein naar wees, hoogstens een paar.
	Adressen []string `json:"addresses,omitempty"`
}

// Logboek bewaart de recente vragen en de optelling per apparaat.
type Logboek struct {
	mu      sync.RWMutex
	recent  []Vraag
	max     int
	tellers map[string]*Teller // sleutel: client + "|" + domein
}

func NieuwLogboek(max int) *Logboek {
	if max <= 0 {
		max = 2000
	}
	return &Logboek{max: max, tellers: map[string]*Teller{}}
}

// Noteer verwerkt één vraag. Geeft true terug als dit apparaat dit domein
// nog niet eerder opvroeg — dat is het moment dat de moeite van een
// melding waard is.
func (l *Logboek) Noteer(v Vraag) bool {
	if v.Name == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.recent = append(l.recent, v)
	if len(l.recent) > l.max {
		l.recent = l.recent[len(l.recent)-l.max:]
	}

	sleutel := v.Client + "|" + strings.ToLower(v.Name)
	t, bestond := l.tellers[sleutel]
	if !bestond {
		t = &Teller{Client: v.Client, Name: v.Name, First: v.At}
		l.tellers[sleutel] = t
	}
	t.Count++
	t.Last = v.At
	for _, a := range v.Antwoorden {
		if len(t.Adressen) >= 4 {
			break
		}
		if !bevat(t.Adressen, a) {
			t.Adressen = append(t.Adressen, a)
		}
	}
	return !bestond
}

// Recent geeft de laatste n vragen, nieuwste eerst.
func (l *Logboek) Recent(n int) []Vraag {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if n <= 0 || n > len(l.recent) {
		n = len(l.recent)
	}
	uit := make([]Vraag, 0, n)
	for i := len(l.recent) - 1; i >= len(l.recent)-n; i-- {
		uit = append(uit, l.recent[i])
	}
	return uit
}

// Drukste geeft de domeinen die het vaakst zijn opgevraagd, aflopend.
// Optioneel gefilterd op één apparaat.
func (l *Logboek) Drukste(n int, client string) []Teller {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var uit []Teller
	for _, t := range l.tellers {
		if client != "" && t.Client != client {
			continue
		}
		uit = append(uit, *t)
	}
	sort.Slice(uit, func(a, b int) bool {
		if uit[a].Count != uit[b].Count {
			return uit[a].Count > uit[b].Count
		}
		return uit[a].Last.After(uit[b].Last)
	})
	if n > 0 && len(uit) > n {
		uit = uit[:n]
	}
	return uit
}

// Apparaten geeft per apparaat hoeveel vragen en hoeveel verschillende
// domeinen er langskwamen.
type Apparaat struct {
	Client string `json:"client"`
	// Naam is de apparaatnaam uit de netwerkkaart, als we die kennen. Een
	// IP-adres zegt niemand iets; "Woonkamer TV" wel.
	Naam     string `json:"name"`
	Vragen   int    `json:"queries"`
	Domeinen int    `json:"domains"`
}

func (l *Logboek) Apparaten() []Apparaat {
	l.mu.RLock()
	defer l.mu.RUnlock()

	per := map[string]*Apparaat{}
	for _, t := range l.tellers {
		a := per[t.Client]
		if a == nil {
			a = &Apparaat{Client: t.Client}
			per[t.Client] = a
		}
		a.Vragen += t.Count
		a.Domeinen++
	}
	var uit []Apparaat
	for _, a := range per {
		uit = append(uit, *a)
	}
	sort.Slice(uit, func(a, b int) bool { return uit[a].Vragen > uit[b].Vragen })
	return uit
}

func bevat(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
