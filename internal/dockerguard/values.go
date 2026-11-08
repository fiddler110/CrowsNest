package dockerguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// jsonDepth bounds nesting; create bodies nest about six deep.
const jsonDepth = 32

// strictJSON parses a request body the way the engine (Go's encoding/json)
// will read it, or fails. Go matches object keys to struct fields
// case-insensitively and the last match wins, so {"Source":"/ok","source":"/"}
// is read by the engine as Source="/" while a map lookup here sees "/ok".
// Bodies with two keys that fold to the same name are refused outright, as is
// invalid UTF-8, trailing data and nesting deeper than jsonDepth. Numbers stay
// json.Number so their literal form (integer or not) can be checked.
func strictJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := readValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

func readValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil // nil, bool, string or json.Number
	}
	if depth+1 > jsonDepth {
		return nil, fmt.Errorf("JSON nested deeper than %d", jsonDepth)
	}
	switch d {
	case '{':
		m := map[string]any{}
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := kt.(string)
			if !ok {
				return nil, errors.New("object key is not a string")
			}
			f := foldKey(key)
			if seen[f] {
				return nil, fmt.Errorf("duplicate key %q", key)
			}
			seen[f] = true
			val, err := readValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			m[key] = val
		}
		if _, err := dec.Token(); err != nil { // the closing brace
			return nil, err
		}
		return m, nil
	case '[':
		list := []any{}
		for dec.More() {
			val, err := readValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			list = append(list, val)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return list, nil
	}
	return nil, errors.New("unexpected JSON delimiter")
}

// foldKey maps a key to a form that is equal for every spelling Go's
// case-insensitive field matching could treat as the same: lower case, then
// the smallest member of each rune's Unicode simple-folding orbit (so the
// long s and the Kelvin sign fold to s and k), and the sharp s as "ss".
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		r = unicode.ToLower(r)
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < m {
				m = f
			}
		}
		b.WriteRune(m)
	}
	return strings.NewReplacer("ß", "ss", "ẞ", "ss").Replace(b.String())
}

var intLiteral = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// asInt reads a JSON number written as an integer. 1.0 and 1e3 are not
// integers: the engine would refuse them for an integer field.
func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || !intLiteral.MatchString(string(n)) {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return i, err == nil
}

func numZero(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	f, err := strconv.ParseFloat(string(n), 64)
	return err == nil && f == 0 && !math.IsNaN(f)
}

// isEmpty is null, false, 0, "", [] or {} and nothing else: [{}], [""] and
// {"": ""} are not empty, the engine acts on them.
func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case bool:
		return !t
	case json.Number:
		return numZero(t)
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

func scalarEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case bool:
		return !t
	case json.Number:
		return numZero(t)
	case string:
		return t == ""
	}
	return false
}

// kind is a set of JSON types a rule accepts.
type kind uint8

const (
	kNull kind = 1 << iota
	kBool
	kInt
	kStr
	kList
	kDict
)

func kindOf(v any) kind {
	switch v.(type) {
	case nil:
		return kNull
	case bool:
		return kBool
	case json.Number:
		if _, ok := asInt(v); ok {
			return kInt
		}
		return 0 // a fractional or exponent number is no kind any rule accepts
	case string:
		return kStr
	case []any:
		return kList
	case map[string]any:
		return kDict
	}
	return 0
}

// quote renders request-controlled data for an error message: one line, escaped.
func quote(v any) string {
	if s, ok := v.(string); ok {
		return strconv.Quote(s)
	}
	return strconv.Quote(fmt.Sprint(v))
}
