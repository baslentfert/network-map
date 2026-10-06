package baseline

import (
	"testing"
	"time"

	"netwerksniffer/internal/model"
)

func host(key, ip, naam string, poorten ...int) model.Host {
	h := model.Host{Key: key, IP: ip, MAC: key, Name: naam}
	for _, p := range poorten {
		h.Ports = append(h.Ports, model.Port{Number: p, Service: "test"})
	}
	return h
}

// De eerste ronde is per definitie normaal. Zou hij hier alles melden,
// dan krijg je bij het eerste gebruik twintig waarschuwingen en leer je
// meteen ze te negeren.
func TestEersteRondeMeldtNiets(t *testing.T) {
	b := Nieuw()
	w := Waarneming{Hosts: []model.Host{host("aa", "192.168.0.10", "NAS", 22, 445)}}

	if bev := Vergelijk(w, b); len(bev) != 0 {
		t.Fatalf("kreeg %d bevindingen op een lege basislijn, wil er 0", len(bev))
	}
	b.Leer(w)
	if len(b.Apparaten) != 1 {
		t.Fatalf("na leren %d apparaten, wil er 1", len(b.Apparaten))
	}
}

func TestNieuwApparaatWordtGemeld(t *testing.T) {
	b := Nieuw()
	eerst := Waarneming{Hosts: []model.Host{host("aa", "192.168.0.10", "NAS")}}
	b.Leer(eerst)

	later := Waarneming{Hosts: []model.Host{
		host("aa", "192.168.0.10", "NAS"),
		host("bb", "192.168.0.44", ""),
	}}
	bev := Vergelijk(later, b)
	if len(bev) != 1 || bev[0].Soort != "nieuw-apparaat" {
		t.Fatalf("kreeg %+v, wil één nieuw-apparaat", bev)
	}
	if bev[0].Ernst != ErnstLetOp {
		t.Errorf("ernst = %q, wil 'let op'", bev[0].Ernst)
	}
}

// Een poort die er gisteren niet was is het signaal waar het om gaat.
func TestNieuwePoortWordtGemeld(t *testing.T) {
	b := Nieuw()
	b.Leer(Waarneming{Hosts: []model.Host{host("aa", "192.168.0.10", "NAS", 22)}})

	bev := Vergelijk(Waarneming{Hosts: []model.Host{
		host("aa", "192.168.0.10", "NAS", 22, 5432),
	}}, b)

	if len(bev) != 1 || bev[0].Soort != "nieuwe-poort" {
		t.Fatalf("kreeg %+v, wil één nieuwe-poort", bev)
	}
	if bev[0].Args["port"] != "5432" {
		t.Errorf("poort = %q, wil 5432", bev[0].Args["port"])
	}
}

// Na leren mag dezelfde situatie niet nóg eens gemeld worden, anders
// blijft de lijst eeuwig rood.
func TestNaLerenGeenHerhaling(t *testing.T) {
	b := Nieuw()
	b.Leer(Waarneming{Hosts: []model.Host{host("aa", "192.168.0.10", "NAS", 22)}})

	w := Waarneming{Hosts: []model.Host{host("aa", "192.168.0.10", "NAS", 22, 5432)}}
	if len(Vergelijk(w, b)) != 1 {
		t.Fatal("eerste keer niet gemeld")
	}
	b.Leer(w)
	if bev := Vergelijk(w, b); len(bev) != 0 {
		t.Errorf("na leren nog %d bevindingen: %+v", len(bev), bev)
	}
}

func TestNieuwDomeinWordtGemeld(t *testing.T) {
	b := Nieuw()
	eerst := Waarneming{
		Hosts:    []model.Host{host("aa", "192.168.0.10", "Camera")},
		Domeinen: map[string][]string{"192.168.0.10": {"tijd.example.com"}},
	}
	b.Leer(eerst)

	bev := Vergelijk(Waarneming{
		Hosts:    []model.Host{host("aa", "192.168.0.10", "Camera")},
		Domeinen: map[string][]string{"192.168.0.10": {"tijd.example.com", "push.vreemd.cn"}},
	}, b)

	if len(bev) != 1 || bev[0].Args["domain"] != "push.vreemd.cn" {
		t.Fatalf("kreeg %+v, wil één nieuw domein push.vreemd.cn", bev)
	}
}

// Hoofdletters mogen geen verschil maken: anders is EXAMPLE.COM elke
// ronde opnieuw "nieuw".
func TestDomeinHoofdletterOngevoelig(t *testing.T) {
	b := Nieuw()
	b.Leer(Waarneming{
		Hosts:    []model.Host{host("aa", "192.168.0.10", "Camera")},
		Domeinen: map[string][]string{"192.168.0.10": {"Tijd.Example.COM"}},
	})
	bev := Vergelijk(Waarneming{
		Hosts:    []model.Host{host("aa", "192.168.0.10", "Camera")},
		Domeinen: map[string][]string{"192.168.0.10": {"tijd.example.com"}},
	}, b)
	if len(bev) != 0 {
		t.Errorf("hetzelfde domein in andere hoofdletters werd gemeld: %+v", bev)
	}
}

// Een apparaat dat één nacht uitstaat is geen nieuws. Pas na een week.
func TestKortWegIsGeenBevinding(t *testing.T) {
	b := Nieuw()
	b.Leer(Waarneming{Hosts: []model.Host{
		host("aa", "192.168.0.10", "NAS"),
		host("bb", "192.168.0.11", "Laptop"),
	}})

	bev := Vergelijk(Waarneming{Hosts: []model.Host{host("aa", "192.168.0.10", "NAS")}}, b)
	if len(bev) != 0 {
		t.Errorf("laptop die even weg is werd gemeld: %+v", bev)
	}

	b.Apparaten["bb"].Laatst = time.Now().Add(-8 * 24 * time.Hour)
	bev = Vergelijk(Waarneming{Hosts: []model.Host{host("aa", "192.168.0.10", "NAS")}}, b)
	if len(bev) != 1 || bev[0].Soort != "verdwenen" {
		t.Errorf("na acht dagen kreeg ik %+v, wil één 'verdwenen'", bev)
	}
}
