package main

import (
	"fmt"
	"strconv"

	"github.com/maxb1906/arpent/internal/diff"
	"github.com/maxb1906/arpent/internal/store"
)

func cmdCompare(e *env, args []string) int {
	fs := e.newFlags("compare")
	site := fs.String("site", "", "")
	from := fs.Int64("from", 0, "")
	to := fs.Int64("to", 0, "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	s, err := e.openSite(*site)
	if err != nil {
		return e.fail(err)
	}
	defer s.Close()
	audits, err := s.Audits()
	if err != nil {
		return e.fail(err)
	}
	var done []store.Audit
	for _, a := range audits {
		if a.Status == store.StatusDone {
			done = append(done, a)
		}
	}
	if len(done) < 2 && (*from == 0 || *to == 0) {
		fmt.Fprintln(e.stdout, e.T("web.compare_need_two"))
		return 1
	}
	if *from == 0 {
		*from = done[len(done)-1].ID
	}
	if *to == 0 {
		*to = done[0].ID
	}
	cs, err := diff.Between(s, *from, *to)
	if err != nil {
		return e.fail(err)
	}
	fmt.Fprintln(e.stdout, e.T("compare.header", "from", strconv.FormatInt(*from, 10), "to", strconv.FormatInt(*to, 10)))
	if len(cs) == 0 {
		fmt.Fprintln(e.stdout, e.T("compare.none"))
		return 0
	}
	printChanges(e, e.stdout, cs)
	return 0
}
