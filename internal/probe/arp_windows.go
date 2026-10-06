package probe

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"

	"netwerksniffer/internal/oui"
)

var (
	modIPHlpAPI       = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable = modIPHlpAPI.NewProc("GetIpNetTable")
)

// mibIPNetRow is MIB_IPNETROW uit iphlpapi.h. Alle velden zijn 4 bytes
// of een array daarvan, dus Go legt hem uit zoals C dat doet.
type mibIPNetRow struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte
	Addr        uint32 // IPv4 in netwerkvolgorde
	Type        uint32
}

// Adressoorten uit de ARP-tabel. Onvolledige entries (INVALID) laten we
// vallen: dat zijn adressen waar Windows nog op antwoord wacht.
const (
	arpTypeInvalid = 2
	arpTypeDynamic = 3
	arpTypeStatic  = 4
)

// ARPEntry is één regel uit de ARP-cache van het besturingssysteem.
type ARPEntry struct {
	IP     string
	MAC    string
	Static bool
	IfIdx  uint32
}

// ARPCache leest de ARP-tabel uit die Windows zelf bijhoudt.
//
// Dit is de goedkoopste manier aan IP↔MAC te komen: geen enkel pakket
// hoeft het netwerk op. De tabel bevat alleen wat deze machine recent
// heeft aangesproken, dus hij is onvolledig — daar is de sweep voor, die
// eerst elk adres aanprikt zodat Windows de cache zelf vult.
func ARPCache() ([]ARPEntry, error) {
	size := uint32(4096)
	for try := 0; try < 6; try++ {
		buf := make([]byte, size)
		r, _, _ := procGetIpNetTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0, // niet sorteren; wij sorteren zelf
		)
		switch r {
		case 0: // NO_ERROR
			return parseARPTable(buf), nil
		case uintptr(windows.ERROR_INSUFFICIENT_BUFFER):
			continue // size is nu bijgewerkt
		case uintptr(windows.ERROR_NO_DATA):
			return nil, nil
		default:
			return nil, fmt.Errorf("GetIpNetTable gaf foutcode %d", r)
		}
	}
	return nil, fmt.Errorf("ARP-tabel bleef groeien tijdens het uitlezen")
}

func parseARPTable(buf []byte) []ARPEntry {
	if len(buf) < 4 {
		return nil
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibIPNetRow{})

	out := make([]ARPEntry, 0, n)
	for i := uint32(0); i < n; i++ {
		off := uintptr(4) + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibIPNetRow)(unsafe.Pointer(&buf[off]))

		if row.Type == arpTypeInvalid || row.PhysAddrLen != 6 {
			continue
		}
		ip := netip.AddrFrom4([4]byte{
			byte(row.Addr), byte(row.Addr >> 8), byte(row.Addr >> 16), byte(row.Addr >> 24),
		})
		mac := oui.Normalize(fmt.Sprintf("%02x%02x%02x%02x%02x%02x",
			row.PhysAddr[0], row.PhysAddr[1], row.PhysAddr[2],
			row.PhysAddr[3], row.PhysAddr[4], row.PhysAddr[5]))

		// Broadcast- en multicastadressen staan als statische regels in de
		// tabel. Dat zijn geen apparaten.
		if mac == "" || oui.IsMulticast(mac) || ip.IsMulticast() {
			continue
		}
		out = append(out, ARPEntry{
			IP:     ip.String(),
			MAC:    mac,
			Static: row.Type == arpTypeStatic,
			IfIdx:  row.Index,
		})
	}
	return out
}
