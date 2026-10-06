// Command makeicon tekent het applicatie-icoon.
//
// Eén bron, drie platformen: Wails leidt het macOS-icns en het Linux-icoon
// af uit build/appicon.png. Alleen Windows gebruikt een eigen icon.ico, en
// die hergebruikt Wails als hij er al staat — vandaar dat we hem hier zelf
// schrijven.
//
// Het icoon wordt per formaat opnieuw getekend in plaats van geschaald.
// Een netwerkkaart met zes knopen is op 256 pixels mooi en op 16 pixels
// een vlek; op kleine maten vallen knopen weg en worden de lijnen dikker,
// zodat de vorm herkenbaar blijft in de taakbalk.
//
// Gebruik: go run ./cmd/makeicon
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

// Kleuren uit de stylesheet van de app. De achtergrond is bewust lichter
// dan de --ground van het venster: een bijna-zwart icoon verdwijnt in een
// donkere taakbalk.
var (
	kleurGrond  = color.RGBA{0x16, 0x21, 0x2E, 0xff}
	kleurLijn   = color.RGBA{0x43, 0x62, 0x7D, 0xff}
	kleurKnoop  = color.RGBA{0xDC, 0xE4, 0xEC, 0xff}
	kleurAccent = color.RGBA{0xD9, 0x8A, 0x1F, 0xff}
)

func main() {
	wortel := "."
	if len(os.Args) > 1 {
		wortel = os.Args[1]
	}

	// De bron voor macOS en Linux, en voor Wails' eigen afgeleiden.
	groot := teken(1024)
	schrijfPNG(filepath.Join(wortel, "build", "appicon.png"), groot)

	// Windows wil één bestand met meerdere formaten erin. De kleinste
	// maten zijn wat je in de taakbalk en de titelbalk ziet.
	maten := []int{16, 24, 32, 48, 64, 128, 256}
	var lagen []*image.RGBA
	for _, m := range maten {
		lagen = append(lagen, teken(m))
	}
	schrijfICO(filepath.Join(wortel, "build", "windows", "icon.ico"), lagen)

	fmt.Println("appicon.png      1024x1024   (macOS, Linux, en bron voor Wails)")
	fmt.Printf("windows/icon.ico %v\n", maten)
}

// vorm beschrijft hoeveel detail er bij een bepaalde maat past.
type vorm struct {
	knopen   int
	marge    float64 // transparante rand; macOS verwacht lucht om het icoon
	hoek     float64 // afronding van het vierkant
	ring     float64 // afstand van de satellieten tot het midden
	rMidden  float64
	rKnoop   float64
	dikteLij float64
	dikteRng float64
	// grillig maakt de ring ongelijkmatig, zodat het op een krachtenmodel
	// lijkt in plaats van op een wiel. Onder een bepaalde maat is dat
	// alleen maar rommelig.
	grillig bool
	// gevuld tekent de satellieten als stip in plaats van als ring. Een
	// ring van twee pixels breed is op taakbalkformaat geen ring meer maar
	// een grijze vlek.
	gevuld bool
}

func vormVoor(maat int) vorm {
	switch {
	case maat <= 20:
		// Taakbalkformaat: alleen nog de kern van de vorm, en stippen.
		return vorm{knopen: 4, marge: 0.0, hoek: 0.26, ring: 0.315,
			rMidden: 0.135, rKnoop: 0.105, dikteLij: 0.055, gevuld: true}
	case maat <= 36:
		return vorm{knopen: 5, marge: 0.02, hoek: 0.24, ring: 0.325,
			rMidden: 0.120, rKnoop: 0.090, dikteLij: 0.042, gevuld: true}
	case maat <= 64:
		return vorm{knopen: 6, marge: 0.05, hoek: 0.22, ring: 0.305,
			rMidden: 0.108, rKnoop: 0.068, dikteLij: 0.025, dikteRng: 0.040}
	default:
		return vorm{knopen: 6, marge: 0.06, hoek: 0.22, ring: 0.325,
			rMidden: 0.088, rKnoop: 0.058, dikteLij: 0.020, dikteRng: 0.034,
			grillig: true}
	}
}

// afwijking maakt de ring onregelmatig, in afstand én in hoek. Zonder dat
// tweede blijft het een wiel: gelijke tussenruimtes lezen als een diagram,
// ongelijke als een kaart van iets dat er echt staat. Vaste waarden, zodat
// elk formaat en elke build hetzelfde icoon oplevert.
var afwijking = []float64{1.00, 0.80, 1.14, 0.88, 1.06, 0.83}

// hoekdraai is de verschuiving per knoop, in delen van de onderlinge hoek.
var hoekdraai = []float64{0.00, 0.10, -0.08, 0.06, -0.11, 0.09}

func teken(maat int) *image.RGBA {
	// Alles wordt op acht keer de grootte getekend en daarna teruggebracht.
	// Dat levert de antialiasing op zonder dat we per vorm randen hoeven
	// te berekenen.
	const ss = 8
	S := float64(maat * ss)
	c := nieuwDoek(maat*ss, maat*ss)
	v := vormVoor(maat)

	marge := v.marge * S
	vlak := S - 2*marge
	c.afgerondVierkant(marge, marge, vlak, vlak, v.hoek*vlak, kleurGrond)

	mx, my := S/2, S/2
	ring := v.ring * S

	type punt struct{ x, y float64 }
	punten := make([]punt, 0, v.knopen)
	for i := 0; i < v.knopen; i++ {
		// Vanaf bovenaan, met de klok mee.
		stap := 2 * math.Pi / float64(v.knopen)
		hoek := -math.Pi/2 + stap*float64(i)
		r := ring
		if v.grillig {
			r *= afwijking[i%len(afwijking)]
			hoek += stap * hoekdraai[i%len(hoekdraai)]
		}
		punten = append(punten, punt{mx + math.Cos(hoek)*r, my + math.Sin(hoek)*r})
	}

	// Eerst de verbindingen, zodat de knopen er bovenop liggen.
	for _, p := range punten {
		c.lijn(mx, my, p.x, p.y, v.dikteLij*S, kleurLijn)
	}

	// Satellieten. Open ringen op grote maten, gevulde stippen zodra een
	// ring te dun zou worden om nog als ring te lezen.
	for _, p := range punten {
		if v.gevuld {
			c.schijf(p.x, p.y, v.rKnoop*S, kleurKnoop)
			continue
		}
		// De achtergrondkleur erin, zodat de lijn eronder niet doorschijnt.
		c.schijf(p.x, p.y, v.rKnoop*S, kleurGrond)
		c.ring(p.x, p.y, v.rKnoop*S, v.dikteRng*S, kleurKnoop)
	}

	// De gateway in het midden, in het accent van de app.
	c.schijf(mx, my, v.rMidden*S, kleurAccent)

	return c.verklein(ss)
}

// --- tekengereedschap -----------------------------------------------------

type doek struct {
	w, h int
	img  *image.RGBA
}

func nieuwDoek(w, h int) *doek {
	return &doek{w: w, h: h, img: image.NewRGBA(image.Rect(0, 0, w, h))}
}

// zet mengt een ondoorzichtige kleur over wat er al stond.
func (d *doek) zet(x, y int, k color.RGBA) {
	if x < 0 || y < 0 || x >= d.w || y >= d.h {
		return
	}
	d.img.SetRGBA(x, y, k)
}

func (d *doek) vul(x0, y0, x1, y1 float64, binnen func(x, y float64) bool, k color.RGBA) {
	ix0, iy0 := int(math.Floor(x0)), int(math.Floor(y0))
	ix1, iy1 := int(math.Ceil(x1)), int(math.Ceil(y1))
	for y := iy0; y <= iy1; y++ {
		for x := ix0; x <= ix1; x++ {
			if binnen(float64(x)+0.5, float64(y)+0.5) {
				d.zet(x, y, k)
			}
		}
	}
}

func (d *doek) schijf(cx, cy, r float64, k color.RGBA) {
	rr := r * r
	d.vul(cx-r, cy-r, cx+r, cy+r, func(x, y float64) bool {
		dx, dy := x-cx, y-cy
		return dx*dx+dy*dy <= rr
	}, k)
}

func (d *doek) ring(cx, cy, r, dikte float64, k color.RGBA) {
	buiten := r + dikte/2
	binnen := r - dikte/2
	bo, bi := buiten*buiten, binnen*binnen
	d.vul(cx-buiten, cy-buiten, cx+buiten, cy+buiten, func(x, y float64) bool {
		dx, dy := x-cx, y-cy
		q := dx*dx + dy*dy
		return q <= bo && q >= bi
	}, k)
}

// lijn tekent een dikke lijn met ronde uiteinden.
func (d *doek) lijn(x1, y1, x2, y2, dikte float64, k color.RGBA) {
	r := dikte / 2
	vx, vy := x2-x1, y2-y1
	lengte2 := vx*vx + vy*vy
	minx, maxx := math.Min(x1, x2)-r, math.Max(x1, x2)+r
	miny, maxy := math.Min(y1, y2)-r, math.Max(y1, y2)+r

	d.vul(minx, miny, maxx, maxy, func(x, y float64) bool {
		if lengte2 == 0 {
			dx, dy := x-x1, y-y1
			return dx*dx+dy*dy <= r*r
		}
		// Projectie van het punt op het lijnstuk, geknipt op de uiteinden.
		t := ((x-x1)*vx + (y-y1)*vy) / lengte2
		t = math.Max(0, math.Min(1, t))
		px, py := x1+t*vx, y1+t*vy
		dx, dy := x-px, y-py
		return dx*dx+dy*dy <= r*r
	}, k)
}

func (d *doek) afgerondVierkant(x, y, w, h, straal float64, k color.RGBA) {
	d.vul(x, y, x+w, y+h, func(px, py float64) bool {
		// Afstand tot de binnenrechthoek; binnen de hoekcirkels telt mee.
		dx := math.Max(math.Max(x+straal-px, px-(x+w-straal)), 0)
		dy := math.Max(math.Max(y+straal-py, py-(y+h-straal)), 0)
		if px < x || py < y || px > x+w || py > y+h {
			return false
		}
		return dx*dx+dy*dy <= straal*straal
	}, k)
}

// verklein middelt blokken van ss bij ss pixels. Daar komt de
// antialiasing vandaan, inclusief die van de transparante rand.
func (d *doek) verklein(ss int) *image.RGBA {
	w, h := d.w/ss, d.h/ss
	uit := image.NewRGBA(image.Rect(0, 0, w, h))
	n := float64(ss * ss)

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var r, g, b, a float64
			for dy := 0; dy < ss; dy++ {
				for dx := 0; dx < ss; dx++ {
					c := d.img.RGBAAt(x*ss+dx, y*ss+dy)
					// Vermenigvuldigen met alfa voordat we middelen, anders
					// kleurt de doorzichtige rand naar zwart toe.
					af := float64(c.A) / 255
					r += float64(c.R) * af
					g += float64(c.G) * af
					b += float64(c.B) * af
					a += float64(c.A)
				}
			}
			// image.RGBA bewaart kleuren vóórvermenigvuldigd met alfa. De
			// som hierboven is dat al, dus niet terugdelen: dat maakte de
			// randpixels te licht en gaf een witte gloed rond het icoon.
			uit.SetRGBA(x, y, color.RGBA{
				R: uint8(math.Round(r / n)),
				G: uint8(math.Round(g / n)),
				B: uint8(math.Round(b / n)),
				A: uint8(math.Round(a / n)),
			})
		}
	}
	return uit
}

// --- wegschrijven ---------------------------------------------------------

func schrijfPNG(pad string, img *image.RGBA) {
	os.MkdirAll(filepath.Dir(pad), 0o755)
	f, err := os.Create(pad)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fout:", err)
		os.Exit(1)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		fmt.Fprintln(os.Stderr, "fout:", err)
		os.Exit(1)
	}
}

// schrijfICO bouwt een Windows-icoonbestand met meerdere formaten.
//
// De afbeeldingen gaan er als PNG in. Dat ondersteunt Windows sinds Vista
// voor elk formaat, en het scheelt de omweg via een omgekeerd opgeslagen
// bitmap met losse maskerlaag.
func schrijfICO(pad string, lagen []*image.RGBA) {
	var blokken [][]byte
	for _, img := range lagen {
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			fmt.Fprintln(os.Stderr, "fout:", err)
			os.Exit(1)
		}
		blokken = append(blokken, buf.Bytes())
	}

	var uit bytes.Buffer
	binary.Write(&uit, binary.LittleEndian, uint16(0))            // gereserveerd
	binary.Write(&uit, binary.LittleEndian, uint16(1))            // 1 = icoon
	binary.Write(&uit, binary.LittleEndian, uint16(len(blokken))) // aantal

	offset := 6 + 16*len(blokken)
	for i, blok := range blokken {
		b := lagen[i].Bounds()
		// 256 wordt als 0 genoteerd; breder past niet in één byte.
		breedte, hoogte := byte(b.Dx()), byte(b.Dy())
		if b.Dx() >= 256 {
			breedte = 0
		}
		if b.Dy() >= 256 {
			hoogte = 0
		}
		uit.WriteByte(breedte)
		uit.WriteByte(hoogte)
		uit.WriteByte(0)                                    // aantal kleuren: 0 bij truecolor
		uit.WriteByte(0)                                    // gereserveerd
		binary.Write(&uit, binary.LittleEndian, uint16(1))  // vlakken
		binary.Write(&uit, binary.LittleEndian, uint16(32)) // bits per pixel
		binary.Write(&uit, binary.LittleEndian, uint32(len(blok)))
		binary.Write(&uit, binary.LittleEndian, uint32(offset))
		offset += len(blok)
	}
	for _, blok := range blokken {
		uit.Write(blok)
	}

	os.MkdirAll(filepath.Dir(pad), 0o755)
	if err := os.WriteFile(pad, uit.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "fout:", err)
		os.Exit(1)
	}
}
