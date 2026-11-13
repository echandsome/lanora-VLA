package netcfg

// Check is the outcome of one step of Preflight.
type Check struct {
	Name   string
	OK     bool
	Detail string // what was found, in a sentence
}
