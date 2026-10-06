// Package capture verzorgt het passief meeluisteren op een adapter.
//
// Dit deel heeft Npcap nodig. gopacket laadt wpcap.dll op runtime — er is
// dus geen SDK en geen cgo bij het bouwen betrokken, en de app draait
// prima zonder Npcap: alleen de passieve laag blijft dan uit.
package capture

import (
	"strings"
	"sync"

	"github.com/gopacket/gopacket/pcap"
)

var (
	checkOnce sync.Once
	available bool
	reason    string
)

// Available zegt of er passief geluisterd kan worden, en zo niet waarom
// niet. Het antwoord is bedoeld om aan de gebruiker te tonen, dus geen
// technische foutmelding maar een volgende stap.
func Available() (bool, string) {
	checkOnce.Do(func() {
		devs, err := pcap.FindAllDevs()
		switch {
		case err != nil && strings.Contains(err.Error(), "wpcap.dll"):
			reason = "Npcap is niet geïnstalleerd. Haal het op bij npcap.com; de rest van de app werkt gewoon door."
		case err != nil:
			reason = "Npcap gevonden maar niet bruikbaar: " + err.Error()
		case len(devs) == 0:
			reason = "Npcap draait, maar geeft geen adapters vrij. Start de app als administrator."
		default:
			available = true
		}
	})
	return available, reason
}

// Devices geeft de adapters zoals pcap ze kent, met hun \Device\NPF_-naam.
func Devices() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}
