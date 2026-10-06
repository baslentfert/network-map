// Command rawtest beantwoordt één vraag: levert een Windows raw socket met
// SIO_RCVALL genoeg op om apparaatnamen uit het verkeer te vissen, zonder
// Npcap te installeren?
//
// Het luistert een halve minuut mee en telt welke naamdragende protocollen
// langskomen: DHCP (hostnaam bij het joinen), mDNS, SSDP, LLMNR en NetBIOS.
// Komt daar niets uit, dan geeft Windows broadcast en multicast niet door
// op deze route en is Npcap de enige weg.
//
// Vereist administratorrechten — raw sockets zijn dat op Windows nu eenmaal.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"netwerksniffer/internal/netif"
)

const (
	sioRcvAll = 0x98000001
	rcvallOn  = 1
)

type teller struct {
	pakketten int
	bytes     int
	bronnen   map[string]bool
}

func main() {
	duur := 30 * time.Second
	if len(os.Args) > 1 {
		if d, err := time.ParseDuration(os.Args[1]); err == nil {
			duur = d
		}
	}

	iface, err := netif.Primary()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fout:", err)
		os.Exit(1)
	}
	fmt.Printf("Luisteren op %s (%s) gedurende %s\n\n", iface.Name, iface.IP, duur)

	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		fmt.Fprintln(os.Stderr, "raw socket openen mislukt:", err)
		fmt.Fprintln(os.Stderr, "\nDit vraagt administratorrechten. Start opnieuw als administrator.")
		os.Exit(1)
	}
	defer windows.Closesocket(fd)

	var adres [4]byte
	copy(adres[:], parseIPv4(iface.IP))
	if err := windows.Bind(fd, &windows.SockaddrInet4{Addr: adres}); err != nil {
		fmt.Fprintln(os.Stderr, "binden aan", iface.IP, "mislukt:", err)
		os.Exit(1)
	}

	// SIO_RCVALL zet de kaart in promiscuous modus op IP-niveau. Vanaf hier
	// zou al het IPv4-verkeer binnen moeten komen dat de adapter ziet.
	var in uint32 = rcvallOn
	var uit uint32
	var teruggegeven uint32
	err = windows.WSAIoctl(fd, sioRcvAll,
		(*byte)(unsafe.Pointer(&in)), 4,
		(*byte)(unsafe.Pointer(&uit)), 4,
		&teruggegeven, nil, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "SIO_RCVALL weigerde:", err)
		fmt.Fprintln(os.Stderr, "\nZonder administratorrechten staat Windows dit niet toe.")
		os.Exit(1)
	}

	interessant := map[uint16]string{
		67: "DHCP (server)", 68: "DHCP (client)",
		5353: "mDNS", 5355: "LLMNR", 1900: "SSDP",
		137: "NetBIOS-NS", 138: "NetBIOS-DGM", 3702: "WS-Discovery",
	}

	tellers := map[string]*teller{}
	andereUDP := map[uint16]int{}
	totaal, broadcastMulticast := 0, 0

	buf := make([]byte, 65535)
	stop := time.Now().Add(duur)
	tv := windows.Timeval{Sec: 2}
	windows.SetsockoptTimeval(fd, windows.SOL_SOCKET, windows.SO_RCVTIMEO, &tv)

	for time.Now().Before(stop) {
		// Recvfrom, niet Read: windows.Socket levert een overlapped socket
		// op, en ReadFile daarop geeft stil nul bytes terug. Dat leverde
		// eerder een lege meting op die eruitzag als "Windows blokkeert
		// alles", terwijl het gewoon de verkeerde aanroep was.
		n, _, err := windows.Recvfrom(fd, buf, 0)
		if err != nil || n < 20 {
			continue
		}
		totaal++

		hl := int(buf[0]&0x0f) * 4
		if hl < 20 || n < hl {
			continue
		}
		proto := buf[9]
		src := fmt.Sprintf("%d.%d.%d.%d", buf[12], buf[13], buf[14], buf[15])
		dstEerste := buf[16]
		// 224–239 is multicast, 255.255.255.255 is broadcast.
		if dstEerste >= 224 || (buf[16] == 255 && buf[17] == 255) {
			broadcastMulticast++
		}
		if proto != 17 || n < hl+8 {
			continue
		}
		sp := binary.BigEndian.Uint16(buf[hl : hl+2])
		dp := binary.BigEndian.Uint16(buf[hl+2 : hl+4])

		naam := ""
		if l, ok := interessant[dp]; ok {
			naam = l
		} else if l, ok := interessant[sp]; ok {
			naam = l
		}
		if naam == "" {
			andereUDP[dp]++
			continue
		}
		t := tellers[naam]
		if t == nil {
			t = &teller{bronnen: map[string]bool{}}
			tellers[naam] = t
		}
		t.pakketten++
		t.bytes += n
		t.bronnen[src] = true
	}

	fmt.Printf("%d IP-pakketten gezien, waarvan %d broadcast of multicast.\n\n", totaal, broadcastMulticast)

	if len(tellers) == 0 {
		fmt.Println("GEEN naamdragende protocollen opgevangen.")
		fmt.Println()
		fmt.Println("Als er wel gewoon verkeer langskwam maar geen broadcast of multicast,")
		fmt.Println("dan geeft Windows die via SIO_RCVALL niet door en is Npcap de enige weg.")
		return
	}

	fmt.Printf("%-16s %10s %10s  %s\n", "PROTOCOL", "PAKKETTEN", "BYTES", "AFKOMSTIG VAN")
	var namen []string
	for k := range tellers {
		namen = append(namen, k)
	}
	sort.Strings(namen)
	for _, k := range namen {
		t := tellers[k]
		var bronnen []string
		for b := range t.bronnen {
			bronnen = append(bronnen, b)
		}
		sort.Strings(bronnen)
		if len(bronnen) > 4 {
			bronnen = append(bronnen[:4], fmt.Sprintf("+%d meer", len(t.bronnen)-4))
		}
		fmt.Printf("%-16s %10d %10d  %v\n", k, t.pakketten, t.bytes, bronnen)
	}

	fmt.Println("\nOordeel:")
	if broadcastMulticast > 0 {
		fmt.Println("  Broadcast en multicast komen door. Namen uit mDNS, SSDP, LLMNR en")
		fmt.Println("  DHCP zijn dus te oogsten zonder Npcap. ARP en LLDP blijven onbereikbaar:")
		fmt.Println("  die zitten onder de IP-laag en komen hier per definitie niet langs.")
	} else {
		fmt.Println("  Alleen unicast. Voor naamontdekking is dit onvoldoende.")
	}
}

func parseIPv4(s string) []byte {
	var b [4]byte
	deel, idx := 0, 0
	for i := 0; i < len(s) && idx < 4; i++ {
		if s[i] == '.' {
			b[idx] = byte(deel)
			deel, idx = 0, idx+1
			continue
		}
		deel = deel*10 + int(s[i]-'0')
	}
	if idx < 4 {
		b[idx] = byte(deel)
	}
	return b[:]
}
