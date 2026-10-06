package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		// De echte titel zet de app bij het opstarten, in de gekozen taal.
		Title:     "Network Map",
		Width:     1280,
		Height:    860,
		MinWidth:  980,
		MinHeight: 620,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		// Achtergrond gelijk aan de donkere --ground uit de stylesheet,
		// zodat het venster niet wit opflitst voordat de CSS geladen is.
		BackgroundColour: &options.RGBA{R: 0x0B, G: 0x10, B: 0x17, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		println("Fout:", err.Error())
	}
}
