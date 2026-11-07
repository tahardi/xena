package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
)

const keyFields = 2

var (
	errMissingList    = errors.New("missing map")
	errUnknownElement = errors.New("unknown map element")
)

type nftConcat struct {
	Concat []json.RawMessage `json:"concat"`
}

type nftMapKey struct {
	nftConcat

	Elem struct {
		Val nftConcat `json:"val"`
	} `json:"elem"`
}

type nftMap struct {
	Elem [][2]nftMapKey `json:"elem"`
}

type nftItem struct {
	Map *nftMap `json:"map"`
}

type nftOutput struct {
	Nftables []nftItem `json:"nftables"`
}

type exposedKey struct {
	from string
	port int
}

func parseOutput(out []byte) (nftOutput, error) {
	var parsed nftOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nftOutput{}, fmt.Errorf("parsing nft output: %w", err)
	}

	return parsed, nil
}

func parseExposed(out []byte) ([]exposedKey, error) {
	parsed, err := parseOutput(out)
	if err != nil {
		return nil, err
	}

	for _, item := range parsed.Nftables {
		if item.Map != nil {
			return parseKeys(item.Map.Elem)
		}
	}

	return nil, fmt.Errorf("parsing nft output: %w", errMissingList)
}

func parseKeys(elements [][2]nftMapKey) ([]exposedKey, error) {
	keys := make([]exposedKey, 0, len(elements))
	for _, element := range elements {
		key, err := parseKey(element[0])
		if err != nil {
			return nil, fmt.Errorf("parsing nft output: %w", err)
		}

		keys = append(keys, key)
	}

	return keys, nil
}

func parseKey(key nftMapKey) (exposedKey, error) {
	concat := key.Concat
	if concat == nil {
		concat = key.Elem.Val.Concat
	}

	if len(concat) != keyFields {
		return exposedKey{}, errUnknownElement
	}

	var parsed exposedKey
	if err := json.Unmarshal(concat[0], &parsed.from); err != nil {
		return exposedKey{}, err
	}

	if err := json.Unmarshal(concat[1], &parsed.port); err != nil {
		return exposedKey{}, err
	}

	return parsed, nil
}
