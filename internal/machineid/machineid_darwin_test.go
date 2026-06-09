//go:build darwin

package machineid

import "testing"

func TestParseIOPlatformUUID(t *testing.T) {
	const sample = `+-o IOPlatformExpertDevice  <class IOPlatformExpertDevice>
    {
      "IOPolledInterface" = "AppleARMWatchdog... is not serializable"
      "IOPlatformUUID" = "564D81A7-FEC9-4B5E-9A12-AB12CD34EF56"
      "IOBusyInterest" = "IOCommand is not serializable"
    }`
	if got := parseIOPlatformUUID(sample); got != "564D81A7-FEC9-4B5E-9A12-AB12CD34EF56" {
		t.Fatalf("parseIOPlatformUUID = %q", got)
	}
	if got := parseIOPlatformUUID("no uuid on any line"); got != "" {
		t.Fatalf("expected empty for missing UUID, got %q", got)
	}
	if got := parseIOPlatformUUID(`      "IOPlatformUUID" = ""`); got != "" {
		t.Fatalf("expected empty for empty-value UUID, got %q", got)
	}
}
