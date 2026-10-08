package main

import "testing"

func TestAutoCallCountMatchesAndroidPolicy(t *testing.T) {
	cases := map[int]int{18: 1, 27: 1, 54: 2, 81: 3, 108: 4, 126: 5}
	for workers, want := range cases {
		if got := autoCallCount(workers); got != want {
			t.Fatalf("workers=%d: got %d calls, want %d", workers, got, want)
		}
	}
}

func TestDefaultsMatchOriginalCSQTT(t *testing.T) {
	var c Config
	defaults(&c)
	if c.VKHashMode != "auto_api" { t.Fatalf("VK hash mode=%q, want auto_api", c.VKHashMode) }
	if c.Obfs != "video" { t.Fatalf("obfs=%q, want video", c.Obfs) }
	if c.Fingerprint != "firefox" { t.Fatalf("fingerprint=%q, want firefox", c.Fingerprint) }
	if c.ClientIDs != "8202606,6287487" { t.Fatalf("client_ids=%q, want original pair", c.ClientIDs) }
	if c.VKAuthMode != "vkcalls" { t.Fatalf("VK auth mode=%q, want vkcalls", c.VKAuthMode) }
}
