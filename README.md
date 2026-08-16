# WinHealth

## Djupgående boot-spårning

WinHealth använder Windows inbyggda `wpr.exe` för att spela in en ETW-spårning
över en omstart. För automatisk analys av ETL-filen krävs **WPA Exporter**, som
installeras med Microsoft Windows Performance Toolkit (WPT) via Windows ADK.
Programmet identifierar `wpaexporter.exe` och `wpa.exe` automatiskt i normala
installationssökvägar och visar tydligt om WPT saknas.

WPA Exporter kan inte återdistribueras som en del av WinHealth. Installera WPT
från [Microsofts officiella ADK-sida](https://learn.microsoft.com/windows-hardware/get-started/adk-install).

Flödet är: schemalägg boot-profiler → starta om → verifiera aktiv WPR-inspelning
→ spara en unik ETL-fil → analysera processernas CPU-tid med WPA Exporter.
Nätverks-, domän-, DNS-, SMB- och GPO-fel kompletteras från Windows eventloggar
inom den uppmätta boot-sessionen. Rapporten anger alltid källan och hittar inte
på mätvärden när ETL-analys saknas.

## About

This is the official Wails Vanilla-TS template.

You can configure the project by editing `wails.json`. More information about the project settings can be found
here: https://wails.io/docs/reference/project-config

## Live Development

To run in live development mode, run `wails dev` in the project directory. This will run a Vite development
server that will provide very fast hot reload of your frontend changes. If you want to develop in a browser
and have access to your Go methods, there is also a dev server that runs on http://localhost:34115. Connect
to this in your browser, and you can call your Go code from devtools.

## Building

To build a redistributable, production mode package, use `wails build`.
