package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const dropPrefix = "xena-drop: "

type Drop struct {
	Time    time.Time
	In      string
	Out     string
	Src     string
	Dst     string
	Proto   string
	DstPort int
	SYN     bool
	ACK     bool
}

type JournalDrops struct {
	journalctl string
}

func NewJournalDrops(journalctl string) *JournalDrops {
	return &JournalDrops{journalctl: journalctl}
}

func (j *JournalDrops) Drops(ctx context.Context, since time.Time) ([]Drop, error) {
	// #nosec G204 -- j.journalctl is fixed by the caller, and every other argument is a constant or an integer.
	out, err := exec.CommandContext(
		ctx,
		j.journalctl,
		"-k",
		"-o", "json",
		"--no-pager",
		"--since", "@"+strconv.FormatInt(since.Unix(), 10),
	).Output()
	if err != nil {
		return nil, fmt.Errorf("running journalctl: %w", err)
	}

	drops := []Drop{}
	for line := range bytes.Lines(out) {
		drop, ok, err := parseJournalLine(line)
		if err != nil {
			return nil, err
		}

		if ok {
			drops = append(drops, drop)
		}
	}

	return drops, nil
}

func parseJournalLine(line []byte) (Drop, bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil {
		return Drop{}, false, fmt.Errorf("decoding journal entry: %w", err)
	}

	var message string
	if err := json.Unmarshal(fields["MESSAGE"], &message); err != nil {
		return Drop{}, false, nil
	}

	drop, ok := ParseDrop(message)
	if !ok {
		return Drop{}, false, nil
	}

	var stamp string
	if err := json.Unmarshal(fields["__REALTIME_TIMESTAMP"], &stamp); err != nil {
		return Drop{}, false, fmt.Errorf("decoding journal entry: %w", err)
	}

	micros, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return Drop{}, false, fmt.Errorf("decoding journal entry: %w", err)
	}

	drop.Time = time.UnixMicro(micros)

	return drop, true, nil
}

func ParseDrop(message string) (Drop, bool) {
	_, rest, found := strings.Cut(message, dropPrefix)
	if !found {
		return Drop{}, false
	}

	var drop Drop
	for field := range strings.FieldsSeq(rest) {
		key, value, _ := strings.Cut(field, "=")
		switch key {
		case "IN":
			drop.In = value
		case "OUT":
			drop.Out = value
		case "SRC":
			drop.Src = value
		case "DST":
			drop.Dst = value
		case "PROTO":
			drop.Proto = value
		case "DPT":
			drop.DstPort, _ = strconv.Atoi(value)
		case "SYN":
			drop.SYN = true
		case "ACK":
			drop.ACK = true
		}
	}

	return drop, true
}
