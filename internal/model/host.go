// Package model bevat de datatypes die backend en frontend delen.
// Wails genereert hier TypeScript-definities uit, dus de json-tags zijn
// meteen de veldnamen in React.
package model

import "time"

// Status is wat de kaart met kleur toont. Elke status krijgt in de UI ook
// een glyph en een label, zodat kleur nooit de enige drager is.
type Status string

const (
	StatusOnline  Status = "online"
	StatusNew     Status = "new"
	StatusAlert   Status = "alert"
	StatusOffline Status = "offline"
)

// Kind bepaalt de glyph in het knooppunt. Geraden uit open poorten,
// geadverteerde diensten en het OUI-blok; "unknown" is een geldig antwoord.
type Kind string

const (
	KindRouter  Kind = "router"
	KindAP      Kind = "ap"
	KindPC      Kind = "pc"
	KindPhone   Kind = "phone"
	KindTV      Kind = "tv"
	KindNAS     Kind = "nas"
	KindIoT     Kind = "iot"
	KindUnknown Kind = "unknown"
)

// Origin zegt waar een naam vandaan komt. De UI toont dit naast de naam,
// zodat zichtbaar blijft of iets gevonden of verzonnen is.
const (
	OriginAlias = "eigen naam"
	OriginMDNS  = "mdns"
	// OriginMDNSHost is de hostnaam uit een A- of PTR-record. Zwakker dan
	// OriginMDNS, want dat is de naam die iemand zelf koos: "Bas's MacBook
	// Pro" leest prettiger dan "Alexs-MacBook-Pro".
	OriginMDNSHost = "mdns-host"
	OriginDHCP     = "dhcp"
	OriginNetBIOS  = "netbios"
	OriginSSDP     = "ssdp"
	OriginWSD      = "ws-discovery"
	OriginRDNS     = "rdns"
	OriginARP      = "arp"
)

// NameSource koppelt een gevonden naam aan zijn herkomst.
type NameSource struct {
	Value  string `json:"value"`
	Origin string `json:"origin"`
}

// Port is een open TCP-poort met de dienst die we erachter vermoeden.
type Port struct {
	Number  int    `json:"number"`
	Service string `json:"service"`
}

// Host is één apparaat op het netwerk.
type Host struct {
	// Key is de stabiele identiteit van deze host, ook in de frontend.
	// Het MAC-adres overleeft een nieuw IP van de DHCP-server, dus dat
	// heeft voorkeur; hosts zonder MAC (WAN-hops, andere subnetten)
	// vallen terug op hun IP.
	Key    string `json:"key"`
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Vendor string `json:"vendor"`
	// Name is de naam die de UI toont: de eigen alias als die er is,
	// anders de sterkste gevonden naam. Leeg betekent echt naamloos.
	Name   string `json:"name"`
	Kind   Kind   `json:"kind"`
	Status Status `json:"status"`

	// Names is de volledige herkomstlijst, sterkste bron eerst.
	Names []NameSource `json:"names"`
	// Model is een modelaanduiding, geen naam. Drie identieke apparaten
	// delen hem, dus hij vervangt de naam niet — hij vult hem aan wanneer
	// er helemaal geen naam te vinden is.
	Model string `json:"model"`
	Ports []Port `json:"ports"`

	TTL    int    `json:"ttl"`
	OSHint string `json:"osHint"`

	// RandomMAC is waar als het locally-administered bit gezet is: het
	// toestel roteert z'n MAC en de fabrikant is niet te bepalen.
	RandomMAC bool `json:"randomMac"`
	IsGateway bool `json:"isGateway"`
	IsSelf    bool `json:"isSelf"`

	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`

	RxBytes uint64 `json:"rxBytes"`
	TxBytes uint64 `json:"txBytes"`

	// NoteKey is de uitleg in het detailpaneel: waarom deze host is wat
	// hij is. Een tekstsleutel, geen zin — de frontend maakt er een zin
	// van in de taal die op dat moment gekozen is.
	NoteKey  string            `json:"noteKey"`
	NoteArgs map[string]string `json:"noteArgs,omitempty"`
}

// Event is één regel in het logboek.
//
// Er staat geen zin in, maar een sleutel met parameters. Daardoor is het
// logboek niet aan een taal gebonden: schakel je om, dan verandert ook
// alles wat er al staat mee.
type Event struct {
	At  time.Time `json:"at"`
	Tag string    `json:"tag"`
	// Key verwijst naar de tekstcatalogus, bijvoorbeeld "ev.newDevice".
	Key  string            `json:"key"`
	Args map[string]string `json:"args,omitempty"`
	// Host is de Key van de betrokken host, zodat de UI kan doorklikken.
	Host string `json:"host"`
}

// Logboek-tags. Ze staan als filterknop in de UI.
const (
	TagNew   = "nieuw"
	TagGone  = "weg"
	TagAlert = "alert"
	TagDHCP  = "dhcp"
	TagARP   = "arp"
	TagMDNS  = "mdns"
	TagDNS   = "dns"
	TagScan  = "scan"
)

// Link is een verbinding in de topologiegraaf.
type Link struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Kind: "subnet" (afgeleid, want de switch ertussen is onzichtbaar),
	// "lldp" (het apparaat vertelde het zelf) of "hop" (uit traceroute).
	Kind string `json:"kind"`
}

// Graph is wat de kaart tekent.
type Graph struct {
	Hosts []Host `json:"hosts"`
	Links []Link `json:"links"`
	// Subnet is het broadcast-domein waarvan we zeker weten dat het er is.
	Subnet string `json:"subnet"`
}
