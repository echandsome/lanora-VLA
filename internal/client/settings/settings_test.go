package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStore(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := s.Identity()
	if got := s.Settings(); !got.LANPriority || !got.PrivateNetwork || got.Remember {
		t.Fatalf("defaults: %+v", got)
	}

	pw := "room password"
	if err := s.Update(func(st *Settings) { st.Server, st.RoomID, st.Remember = "https://lan.example", "7KQ2MX9DW", true }, &pw); err != nil {
		t.Fatal(err)
	}

	// Reopening yields the same identity, settings and password.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Identity().Equal(id) {
		t.Fatal("identity changed across a restart")
	}
	if got := s2.Settings(); got.Server != "https://lan.example" || got.RoomID != "7KQ2MX9DW" || !got.Remember {
		t.Fatalf("settings not persisted: %+v", got)
	}
	if s2.Password() != pw {
		t.Fatalf("password = %q", s2.Password())
	}

	// Changing other settings keeps the password; turning Remember off
	// forgets it.
	if err := s2.Update(func(st *Settings) { st.RelayOnly = true }, nil); err != nil {
		t.Fatal(err)
	}
	if s2.Password() != pw {
		t.Fatal("password lost by an unrelated change")
	}
	if err := s2.Update(func(st *Settings) { st.Remember = false }, nil); err != nil {
		t.Fatal(err)
	}
	if s2.Password() != "" {
		t.Fatal("password kept after Remember was turned off")
	}

	info, err := os.Stat(filepath.Join(dir, "client.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v, %v", info.Mode(), err)
	}

	// A file whose identity is present but unusable is reported, not
	// replaced.
	os.WriteFile(filepath.Join(dir, "client.json"), []byte(`{"identity":"AAEC"}`), 0o600)
	if _, err := Open(dir); err == nil {
		t.Fatal("an unreadable identity was replaced")
	}

	// A corrupt file is reported, not silently replaced (which would lose
	// the identity and with it the device's addresses).
	os.WriteFile(filepath.Join(dir, "client.json"), []byte("{not json"), 0o600)
	if _, err := Open(dir); err == nil {
		t.Fatal("corrupt state accepted")
	}
}
