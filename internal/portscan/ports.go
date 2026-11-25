package portscan

import (
	"fmt"
	"sort"
)

// Profile est un profil de scan.
type Profile string

// Profils disponibles (§ 5.2).
const (
	Quick    Profile = "quick"    // ≈ 100 ports parmi les plus courants
	Standard Profile = "standard" // 1–1024 + ≈ 400 ports courants au-delà (défaut)
	Full     Profile = "full"     // 1–65535 (long, à confirmer)
)

// Profiles liste les profils dans l'ordre d'affichage.
var Profiles = []Profile{Quick, Standard, Full}

// ParseProfile accepte aussi les noms français.
func ParseProfile(s string) (Profile, error) {
	switch s {
	case "quick", "rapide":
		return Quick, nil
	case "", "standard":
		return Standard, nil
	case "full", "complet":
		return Full, nil
	}
	return "", fmt.Errorf("profil inconnu : %q (quick, standard, full)", s)
}

// quickPorts : services TCP les plus fréquents dans un réseau de PME/maison
// (partage de fichiers, administration, impression, caméras, NAS, IoT…).
// Liste établie à la main à partir des numéros IANA et de l'usage courant.
var quickPorts = []int{
	20, 21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 119, 135, 139, 143, 389, 427, 443, 445,
	465, 515, 548, 554, 587, 631, 636, 873, 902, 990, 993, 995, 1080, 1194, 1433, 1521,
	1723, 1883, 2049, 2082, 2083, 2222, 2375, 2376, 3000, 3128, 3260, 3306, 3389, 4443,
	5000, 5001, 5060, 5061, 5222, 5357, 5432, 5555, 5601, 5672, 5900, 5901, 5985, 5986,
	6379, 6443, 7547, 8000, 8006, 8008, 8009, 8080, 8081, 8088, 8123, 8291, 8443, 8554,
	8728, 8880, 8883, 8888, 9000, 9090, 9100, 9200, 9443, 10000, 11211, 27017, 32400,
	49152, 62078,
}

// extraPorts : services courants au-delà de 1024, ajoutés au profil standard.
var extraPorts = []int{
	1025, 1026, 1027, 1028, 1029, 1030, 1110, 1234, 1311, 1352, 1400, 1414, 1443, 1500,
	1583, 1688, 1720, 1741, 1755, 1801, 1812, 2000, 2001, 2002, 2030, 2100, 2103, 2105,
	2121, 2181, 2200, 2381, 2525, 2601, 2604, 2869, 3001, 3005, 3050, 3052, 3268, 3269,
	3283, 3299, 3300, 3333, 3351, 3388, 3390, 3689, 3690, 3702, 3780, 3784, 4000, 4001,
	4040, 4045, 4125, 4369, 4567, 4664, 4711, 4712, 4840, 4848, 4899, 5004, 5005, 5009,
	5050, 5051, 5101, 5190, 5201, 5280, 5400, 5431, 5433, 5500, 5560, 5631, 5632, 5666,
	5683, 5800, 5801, 5802, 5810, 5815, 5822, 5850, 5859, 5862, 5877, 5902, 5903, 5904,
	5905, 5906, 5907, 5908, 5909, 5910, 5938, 5950, 5984, 6000, 6001, 6002, 6003, 6004,
	6005, 6006, 6007, 6080, 6346, 6463, 6514, 6543, 6566, 6567, 6646, 6666, 6667, 6668,
	6669, 6689, 6699, 6789, 6881, 6901, 7000, 7001, 7002, 7070, 7080, 7100, 7443, 7474,
	7676, 7777, 7778, 7878, 8001, 8002, 8003, 8004, 8005, 8007, 8010, 8020, 8022, 8031,
	8042, 8045, 8060, 8069, 8082, 8083, 8084, 8085, 8086, 8087, 8089, 8090, 8091, 8092,
	8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100, 8112, 8118, 8139, 8161, 8180, 8181,
	8200, 8222, 8333, 8383, 8400, 8402, 8500, 8530, 8531, 8600, 8649, 8686, 8800, 8834,
	8873, 8899, 8983, 8999, 9001, 9002, 9003, 9009, 9010, 9042, 9050, 9080, 9081, 9091,
	9092, 9093, 9099, 9101, 9102, 9103, 9110, 9111, 9152, 9191, 9220, 9290, 9300, 9415,
	9418, 9500, 9535, 9595, 9666, 9876, 9877, 9898, 9900, 9943, 9944, 9998, 9999, 10001,
	10002, 10003, 10010, 10050, 10051, 10080, 10243, 10443, 10566, 11110, 11111, 12000,
	12345, 13579, 14000, 15000, 16080, 16992, 16993, 17000, 17988, 18080, 18264, 19101,
	19350, 20000, 20005, 20031, 20828, 21571, 22222, 23023, 23424, 25565, 25734, 27015,
	27016, 28017, 30000, 30718, 31337, 32768, 32769, 32770, 32771, 33060, 34567, 37777,
	40000, 41794, 44818, 47808, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160,
	50000, 50001, 50002, 50070, 50100, 51413, 52869, 55553, 55555, 60000, 61616, 64738,
}

// Ports renvoie les ports TCP d'un profil, triés et sans doublon.
func (p Profile) Ports() []int {
	set := map[int]bool{}
	switch p {
	case Quick:
		for _, x := range quickPorts {
			set[x] = true
		}
	case Full:
		out := make([]int, 65535)
		for i := range out {
			out[i] = i + 1
		}
		return out
	default:
		for x := 1; x <= 1024; x++ {
			set[x] = true
		}
		for _, x := range quickPorts {
			set[x] = true
		}
		for _, x := range extraPorts {
			set[x] = true
		}
	}
	out := make([]int, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Ints(out)
	return out
}
