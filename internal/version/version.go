// Package version holds build and protocol version information shared by the
// server and the clients.
package version

import (
	"strconv"
	"strings"
)

// Version is the release version. It is overridden at build time with
// -ldflags "-X lanora/internal/version.Version=1.2.3".
var Version = "1.0.0"

// Commit is the source revision the binary was built from, if known.
var Commit = ""

// Publisher is the developer's name as Windows shows it for the installed
// program. Override it with -ldflags "-X lanora/internal/version.Publisher=…".
var Publisher = "Jack"

// Protocol is the control/data protocol revision. A client and a server must
// agree on it; it is only bumped on incompatible wire changes.
const Protocol = 1

// MinClient is the oldest client release this server build accepts.
const MinClient = "1.0.0"

// Compare returns -1, 0 or 1 when a is older than, equal to, or newer than b.
// Versions are dotted decimal ("1.4.2"); a trailing pre-release or build
// suffix ("-rc1", "+meta") is ignored and missing components count as zero.
func Compare(a, b string) int {
	pa, pb := parse(a), parse(b)
	for i := range pa {
		switch {
		case pa[i] < pb[i]:
			return -1
		case pa[i] > pb[i]:
			return 1
		}
	}
	return 0
}

func parse(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	for i, part := range strings.SplitN(v, ".", 3) {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			break
		}
		out[i] = n
	}
	return out
}
