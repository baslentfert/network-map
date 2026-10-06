package probe

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procIcmpCreateFile  = modIPHlpAPI.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = modIPHlpAPI.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = modIPHlpAPI.NewProc("IcmpSendEcho")
)

// ipOptionInformation en icmpEchoReply zijn IP_OPTION_INFORMATION en
// ICMP_ECHO_REPLY uit ipexport.h. De uitlijning die Go hier kiest is
// dezelfde als die van de C-compiler op amd64, dus geen handmatige
// opvulbytes: die zouden het juist stukmaken.
type ipOptionInformation struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData *byte
}

type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          *byte
	Options       ipOptionInformation
}

const icmpStatusSuccess = 0

// PingResult is het antwoord van één host op één echo request.
type PingResult struct {
	IP  string
	RTT time.Duration
	// TTL is de resterende TTL van het antwoord. De meeste stacks
	// vertrekken op 64 (Linux, Android, de meeste IoT), 128 (Windows) of
	// 255 (netwerkapparatuur), dus dit is een ruwe OS-hint.
	TTL   int
	Alive bool
}

// pinger houdt één ICMP-handle vast. IcmpSendEcho blokkeert, en een
// handle delen tussen goroutines is nergens gedocumenteerd als veilig —
// dus krijgt elke worker z'n eigen handle.
type pinger struct {
	h   windows.Handle
	req [32]byte // zelfde payloadgrootte als Windows' eigen ping
	rep [512]byte
}

func newPinger() (*pinger, error) {
	r, _, err := procIcmpCreateFile.Call()
	if windows.Handle(r) == windows.InvalidHandle {
		return nil, err
	}
	p := &pinger{h: windows.Handle(r)}
	for i := range p.req {
		p.req[i] = byte('a' + i%23)
	}
	return p, nil
}

func (p *pinger) Close() {
	procIcmpCloseHandle.Call(uintptr(p.h))
}

// ping stuurt één echo request. Werkt zonder administratorrechten: we
// vragen de ICMP-stack van Windows om het pakket te versturen in plaats
// van zelf een raw socket te openen, en dat mag elke gebruiker.
func (p *pinger) ping(ip netip.Addr, timeout time.Duration) PingResult {
	res := PingResult{IP: ip.String()}
	if !ip.Is4() {
		return res
	}
	b := ip.As4()
	dest := binary.LittleEndian.Uint32(b[:])

	n, _, _ := procIcmpSendEcho.Call(
		uintptr(p.h),
		uintptr(dest),
		uintptr(unsafe.Pointer(&p.req[0])),
		uintptr(len(p.req)),
		0, // geen IP-opties
		uintptr(unsafe.Pointer(&p.rep[0])),
		uintptr(len(p.rep)),
		uintptr(timeout/time.Millisecond),
	)
	if n == 0 {
		return res
	}

	r := (*icmpEchoReply)(unsafe.Pointer(&p.rep[0]))
	if r.Status != icmpStatusSuccess {
		return res
	}
	res.Alive = true
	res.RTT = time.Duration(r.RoundTripTime) * time.Millisecond
	res.TTL = int(r.Options.TTL)
	return res
}

// PingSweep pingt alle opgegeven adressen parallel.
//
// Naast het vinden van hosts heeft dit een tweede doel: elk adres dat
// antwoordt komt daarna in de ARP-cache van Windows te staan, compleet
// met MAC-adres. Zo krijgen we IP↔MAC zonder ooit zelf een ARP-pakket te
// hoeven bouwen — en dus zonder Npcap.
func PingSweep(targets []netip.Addr, workers int, timeout time.Duration, onResult func(PingResult)) {
	if workers <= 0 {
		workers = 64
	}
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}

	jobs := make(chan netip.Addr, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := newPinger()
			if err != nil {
				// Zonder handle kan deze worker niets; de anderen gaan door.
				for range jobs {
				}
				return
			}
			defer p.Close()

			for ip := range jobs {
				r := p.ping(ip, timeout)
				if onResult != nil {
					mu.Lock()
					onResult(r)
					mu.Unlock()
				}
			}
		}()
	}
	for _, ip := range targets {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
}
