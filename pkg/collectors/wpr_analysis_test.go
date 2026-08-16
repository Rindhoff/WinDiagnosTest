package collectors

import (
	"testing"
)

func TestParseWPRRecordingStatus(t *testing.T) {
	tests := []struct {
		name                  string
		output                string
		wantRecording         bool
		wantExplicitlyStopped bool
	}{
		{"active English", "WPR is recording...\r\nCollector Name: WPR_initiated", true, false},
		{"inactive English", "WPR is not recording.", false, true},
		{"inactive Swedish", "Ingen inspelning pågår.", false, true},
		{"unknown error", "Access is denied.", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recording, stopped := parseWPRRecordingStatus(tt.output)
			if recording != tt.wantRecording || stopped != tt.wantExplicitlyStopped {
				t.Fatalf("got recording=%v stopped=%v", recording, stopped)
			}
		})
	}
}

func TestValidatedBootProfilesAvoidsDuplicateKernelCollectors(t *testing.T) {
	profiles, err := validatedBootProfiles("GeneralProfile")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"GeneralProfile", "Network", "FileIO"}
	if len(profiles) != len(want) {
		t.Fatalf("got %v, want %v", profiles, want)
	}
	for i := range want {
		if profiles[i] != want[i] {
			t.Fatalf("got %v, want %v", profiles, want)
		}
	}
}

func TestParseWPAProcessCSVData(t *testing.T) {
	csv := "New Process,Count,CPU Usage (in view)\n" +
		"explorer.exe (1234),\"1,500\",123.5\n" +
		"service.exe (4321),250,22.25\n"
	items, err := parseWPAProcessCSVData(csv)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Name != "explorer.exe (1234)" || items[0].DurationMs != 124 || items[0].Count != 1500 {
		t.Fatalf("unexpected result: %#v", items)
	}

	quoted := "New Process;Count;CPU Usage (in view)\nexplorer.exe (1234);1 500;123,5\n"
	items, err = parseWPAProcessCSVData(quoted)
	if err != nil || len(items) != 1 || items[0].DurationMs != 124 || items[0].Count != 1500 {
		t.Fatalf("localized CSV result=%#v err=%v", items, err)
	}
}
