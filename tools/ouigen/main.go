// ouigen convertit le registre IEEE MA-L (oui.txt) en fichier compact
// assets/oui.tsv.gz embarqué dans Arpent (« PREFIXE\tFabricant », trié).
//
//	curl -o oui.txt https://standards-oui.ieee.org/oui/oui.txt
//	go run ./tools/ouigen oui.txt assets/oui.tsv.gz
package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

var line = regexp.MustCompile(`^([0-9A-F]{6})\s+\(base 16\)\s+(.+?)\s*$`)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage : ouigen oui.txt sortie.tsv.gz")
		os.Exit(2)
	}
	in, err := os.Open(os.Args[1])
	check(err)
	defer in.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		if g := line.FindStringSubmatch(sc.Text()); g != nil {
			m[g[1]] = strings.Join(strings.Fields(g[2]), " ")
		}
	}
	check(sc.Err())
	if len(m) < 10000 {
		check(fmt.Errorf("seulement %d entrées : fichier inattendu", len(m)))
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out, err := os.Create(os.Args[2])
	check(err)
	zw, _ := gzip.NewWriterLevel(out, gzip.BestCompression)
	bw := bufio.NewWriter(zw)
	for _, k := range keys {
		fmt.Fprintf(bw, "%s\t%s\n", k, m[k])
	}
	check(bw.Flush())
	check(zw.Close())
	check(out.Close())
	fmt.Printf("%d préfixes écrits dans %s\n", len(keys), os.Args[2])
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
