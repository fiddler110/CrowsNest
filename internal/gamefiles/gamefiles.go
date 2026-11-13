// Package gamefiles lets admins read and edit the config files a module declares (files: in module.yaml).
//
// The panel never mounts game data. A file is read and written with `docker exec` in the game's container, so the
// exec guard must allowlist the exact commands: ReadArgs and WriteArgs build them, and nothing else ever runs. The
// web side names a file by its id, never by a path.
package gamefiles

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Spec is one editable file of a game, as the module declares it.
type Spec struct {
	ID    string `yaml:"id" json:"id"`
	Label string `yaml:"label" json:"label"`
	// Path is absolute, inside the container.
	Path string `yaml:"path" json:"path"`
	// MaxBytes caps the file (default 65536, at most 1 MiB).
	MaxBytes int `yaml:"max_bytes" json:"max_bytes"`
	// Restart says what a change needs: "required" (the default), "none", or any other text, shown as a hint.
	Restart string `yaml:"restart" json:"restart"`
	// StopFirst warns that the game rewrites this file when it stops, so an edit made while it runs may be lost.
	StopFirst bool `yaml:"stop_first" json:"stop_first"`
	// Redact lists regular expressions; for each line one matches, capture group 1 (the value) is hidden in the editor.
	Redact []string `yaml:"redact" json:"-"`
}

const (
	DefaultMaxBytes = 64 << 10
	AbsoluteMax     = 1 << 20
	// Mask replaces a redacted value in what the editor shows.
	Mask = "••••••••"
)

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// Normalize fills defaults and validates every spec of one module (or game). It returns the list to use.
func Normalize(specs []Spec) ([]Spec, error) {
	out := make([]Spec, len(specs))
	seen := map[string]bool{}
	for i, s := range specs {
		if !idRe.MatchString(s.ID) {
			return nil, fmt.Errorf("files[%d]: id %q must match %s", i, s.ID, idRe)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("files[%d]: duplicate id %q", i, s.ID)
		}
		seen[s.ID] = true
		if err := checkPath(s.Path); err != nil {
			return nil, fmt.Errorf("files[%s]: %w", s.ID, err)
		}
		if s.Label == "" {
			s.Label = s.ID
		}
		if s.MaxBytes == 0 {
			s.MaxBytes = DefaultMaxBytes
		}
		if s.MaxBytes < 0 || s.MaxBytes > AbsoluteMax {
			return nil, fmt.Errorf("files[%s]: max_bytes must be 1 to %d", s.ID, AbsoluteMax)
		}
		if s.Restart == "" {
			s.Restart = "required"
		}
		for _, p := range s.Redact {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("files[%s]: redact %q: %v", s.ID, p, err)
			}
			if re.NumSubexp() < 1 {
				return nil, fmt.Errorf("files[%s]: redact %q needs a capture group around the value to hide", s.ID, p)
			}
		}
		out[i] = s
	}
	return out, nil
}

func checkPath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/"):
		return errors.New("path must be an absolute path to a file")
	case strings.ContainsAny(p, "\x00\n\r*?[]{}$`\\\"'") || strings.Contains(p, ".."):
		return errors.New("path has characters that are not allowed (no .., globs or quotes)")
	case strings.Contains(p, "//"):
		return errors.New("path must not contain //")
	}
	for _, bad := range []string{"/proc", "/sys", "/dev"} {
		if p == bad || strings.HasPrefix(p, bad+"/") {
			return fmt.Errorf("path under %s is not allowed", bad)
		}
	}
	return nil
}

// readScript prints the file, or nothing if it does not exist yet (saving then creates it). It reads one byte more
// than the limit so "too large" can be told from "exactly full".
const readScript = `[ -e "$1" ] || exit 0; head -c "$2" -- "$1"`

// ReadArgs is the exact command that prints the file.
func (s Spec) ReadArgs() []string {
	return []string{"sh", "-c", readScript, "sh", s.Path, strconv.Itoa(s.MaxBytes + 1)}
}

// writeScript copies the old file first so the new one keeps its owner and mode, writes stdin to a temp file beside
// it, then renames it over the original, so a reader never sees half a file.
const writeScript = `t="$1.crowsnest-tmp"; { [ ! -e "$1" ] || cp -p -- "$1" "$t"; } && cat > "$t" && mv -f -- "$t" "$1"`

// WriteArgs is the exact command that replaces the file with its standard input.
func (s Spec) WriteArgs() []string {
	return []string{"sh", "-c", writeScript, "sh", s.Path}
}

// ContentEnv is the environment variable that carries the new content into a helper container (which has no
// standard input to write to).
const ContentEnv = "CROWSNEST_FILE_CONTENT"

// helperWriteScript is writeScript for a one-shot container: the content comes from the environment.
const helperWriteScript = `t="$1.crowsnest-tmp"; { [ ! -e "$1" ] || cp -p -- "$1" "$t"; } && printf '%s' "$` + ContentEnv + `" > "$t" && mv -f -- "$t" "$1"`

// HelperReadArgs and HelperWriteArgs are the entrypoints of the one-shot helper container that edits a file of a
// stopped game. The same fixed scripts as the exec ones, never anything a module supplies.
func (s Spec) HelperReadArgs() []string { return s.ReadArgs() }

// HelperWriteArgs: see HelperReadArgs. The content travels in ContentEnv.
func (s Spec) HelperWriteArgs() []string {
	return []string{"/bin/sh", "-c", helperWriteScript, "sh", s.Path}
}

// Hash is the sha256 of content, hex.
func Hash(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

// ErrHiddenValue is returned when a masked line cannot be given its real value back.
var ErrHiddenValue = errors.New("hidden value")

// ErrNotText is returned for a file that is not valid UTF-8 text.
var ErrNotText = errors.New("the file is not UTF-8 text, so it cannot be edited here")

// CheckText refuses binary content.
func CheckText(b []byte) error {
	if !utf8.Valid(b) || strings.IndexByte(string(b), 0) >= 0 {
		return ErrNotText
	}
	return nil
}

func (s Spec) regexps() []*regexp.Regexp {
	var res []*regexp.Regexp
	for _, p := range s.Redact {
		if re, err := regexp.Compile(p); err == nil && re.NumSubexp() >= 1 {
			res = append(res, re)
		}
	}
	return res
}

// secretsIn calls fn for every redacted value in line: the text from the start of the match up to the value (which
// names it, like `AdminPassword="`) and the value's position.
func secretsIn(res []*regexp.Regexp, line string, fn func(prefix string, from, to int)) {
	for _, re := range res {
		for _, m := range re.FindAllStringSubmatchIndex(line, -1) {
			if len(m) >= 4 && m[2] >= 0 {
				fn(line[m[0]:m[2]], m[2], m[3])
			}
		}
	}
}

// replaceSecrets rewrites each redacted value of line with what pick returns for its prefix and current text.
func replaceSecrets(res []*regexp.Regexp, line string, pick func(prefix, value string) string) string {
	type span struct {
		from, to int
		with     string
	}
	var spans []span
	secretsIn(res, line, func(prefix string, from, to int) {
		spans = append(spans, span{from, to, pick(prefix, line[from:to])})
	})
	sort.Slice(spans, func(i, j int) bool { return spans[i].from < spans[j].from })
	var out strings.Builder
	last := 0
	for _, sp := range spans {
		if sp.from < last { // two patterns matched the same text
			continue
		}
		out.WriteString(line[last:sp.from])
		out.WriteString(sp.with)
		last = sp.to
	}
	out.WriteString(line[last:])
	return out.String()
}

// Hide returns content as the editor should show it: every redacted value replaced by Mask.
func (s Spec) Hide(content string) string {
	res := s.regexps()
	if len(res) == 0 {
		return content
	}
	lines := strings.Split(content, "\n")
	for i, l := range lines {
		lines[i] = replaceSecrets(res, l, func(string, string) string { return Mask })
	}
	return strings.Join(lines, "\n")
}

// Restore undoes Hide on submitted text. A value that still shows Mask gets back the value the same setting (the text
// before it, such as `rcon.password=`) has in current, the file as it is now; where it sits in the file does not
// matter. A mask with no counterpart is an error, so the mask is never written.
func (s Spec) Restore(submitted, current string) (string, error) {
	res := s.regexps()
	if len(res) == 0 {
		return submitted, nil
	}
	secrets := map[string]string{} // prefix -> current value
	for _, l := range strings.Split(current, "\n") {
		secretsIn(res, l, func(prefix string, from, to int) {
			if _, dup := secrets[prefix]; !dup {
				secrets[prefix] = l[from:to]
			}
		})
	}
	lines := strings.Split(submitted, "\n")
	for i, l := range lines {
		var bad error
		lines[i] = replaceSecrets(res, l, func(prefix, value string) string {
			if value != Mask {
				return value
			}
			if v, ok := secrets[prefix]; ok {
				return v
			}
			if bad == nil {
				bad = fmt.Errorf("%w: line %d still shows %s for %q, which is no longer in the file: type the real value or remove it", ErrHiddenValue, i+1, Mask, strings.TrimSpace(prefix))
			}
			return value
		})
		if bad != nil {
			return "", bad
		}
	}
	return strings.Join(lines, "\n"), nil
}
