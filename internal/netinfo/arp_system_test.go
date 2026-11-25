//go:build windows || linux

package netinfo

import "testing"

// Lecture réelle de la table ARP du système (aucun paquet envoyé).
func TestARPTableSystem(t *testing.T) {
	n, err := ARPTable()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range n {
		if !e.IP.Is4() || !validMAC(e.MAC) {
			t.Errorf("entrée invalide : %+v", e)
		}
	}
	t.Logf("%d voisins", len(n))
}
