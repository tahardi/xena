package audit

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var errBadUbuntuVersion = errors.New("bad Ubuntu version")

type ubuntuVersion struct {
	major int
	minor int
}

func parseUbuntuVersion(version string) (ubuntuVersion, error) {
	majorText, minorText, ok := strings.Cut(version, ".")
	if !ok {
		return ubuntuVersion{}, fmt.Errorf("parsing %q: %w", version, errBadUbuntuVersion)
	}

	major, err := strconv.Atoi(majorText)
	if err != nil {
		return ubuntuVersion{}, fmt.Errorf("parsing %q: %w", version, errBadUbuntuVersion)
	}

	minor, err := strconv.Atoi(minorText)
	if err != nil {
		return ubuntuVersion{}, fmt.Errorf("parsing %q: %w", version, errBadUbuntuVersion)
	}
	return ubuntuVersion{major: major, minor: minor}, nil
}

func (v ubuntuVersion) atLeast(minimum ubuntuVersion) bool {
	if v.major != minimum.major {
		return v.major > minimum.major
	}
	return v.minor >= minimum.minor
}
