package main

import (
	"embed"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

// getWebviewUserDataPath returns a reliable directory for WebView2 runtime data.
// When WinHealth runs elevated (as Administrator), the default %APPDATA% resolves to
// C:\Users\Administrator\AppData\Roaming, where sandboxed WebView2 worker processes
// are blocked from writing by Windows ACLs. Using ProgramData solves this.
func getWebviewUserDataPath() string {
	progData := os.Getenv("ProgramData")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	targetDir := filepath.Join(progData, "WinHealth", "WebView2")
	if err := os.MkdirAll(targetDir, 0777); err == nil {
		return targetDir
	}

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData != "" {
		targetDir = filepath.Join(localAppData, "WinHealth", "WebView2")
		if err := os.MkdirAll(targetDir, 0777); err == nil {
			return targetDir
		}
	}

	tempDir := filepath.Join(os.TempDir(), "WinHealth_WebView2")
	_ = os.MkdirAll(tempDir, 0777)
	return tempDir
}

func main() {
	// Create an instance of the app structure
	app := NewApp()

	userDataPath := getWebviewUserDataPath()

	// Create application with options
	err := wails.Run(&options.App{
		Title:             "WinHealth Diagnostic Hub - Windows Felsökning & Hälsorapport",
		Width:             1180,
		Height:            820,
		MinWidth:          960,
		MinHeight:         640,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 15, G: 23, B: 42, A: 1},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewUserDataPath:  userDataPath,
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			BackdropType:         windows.Mica,
			Theme:                windows.Dark,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
