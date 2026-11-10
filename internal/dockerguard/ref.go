package dockerguard

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	componentRe = `[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*`
	labelRe     = `[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?`
	domainRe    = regexp.MustCompile(`^(?:` + labelRe + `(?:\.` + labelRe + `)*|\[[0-9a-fA-F:]+\])(?::[0-9]+)?$`)
	componentRx = regexp.MustCompile(`^` + componentRe + `$`)
	tagRe       = regexp.MustCompile(`^[\w][\w.-]{0,127}$`)
	digestRe    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	hubAliases  = map[string]bool{"docker.io": true, "index.docker.io": true, "registry-1.docker.io": true}
)

// parseRef returns the repository, tag and digest of an image reference, the
// repository fully qualified the way the engine stores it: "palworld" is
// docker.io/library/palworld and "index.docker.io/x/y" is docker.io/x/y.
func parseRef(ref string) (repo, tag, digest string, err error) {
	if ref == "" {
		return "", "", "", errors.New("empty image reference")
	}
	name, digest, _ := strings.Cut(ref, "@")
	if digest != "" && !digestRe.MatchString(digest) {
		return "", "", "", fmt.Errorf("bad digest in %q", ref)
	}
	last := name[strings.LastIndex(name, "/")+1:]
	if strings.Contains(last, ":") {
		i := strings.LastIndex(name, ":")
		name, tag = name[:i], name[i+1:]
		if !tagRe.MatchString(tag) {
			return "", "", "", fmt.Errorf("bad tag in %q", ref)
		}
	}
	parts := strings.Split(name, "/")
	first := parts[0]
	var domain string
	var path []string
	if len(parts) > 1 && (strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" || first != strings.ToLower(first)) {
		domain, path = strings.ToLower(first), parts[1:]
		if !domainRe.MatchString(first) {
			return "", "", "", fmt.Errorf("bad registry in %q", ref)
		}
	} else {
		domain, path = "docker.io", parts
	}
	if hubAliases[domain] {
		domain = "docker.io"
		if len(path) == 1 {
			path = []string{"library", path[0]}
		}
	}
	for _, p := range path {
		if !componentRx.MatchString(p) {
			return "", "", "", fmt.Errorf("bad repository in %q", ref)
		}
	}
	return domain + "/" + strings.Join(path, "/"), tag, digest, nil
}

// repoOrNone is the repository of a reference, or "" when it is not one.
func repoOrNone(ref any) string {
	s, ok := ref.(string)
	if !ok {
		return ""
	}
	repo, _, _, err := parseRef(s)
	if err != nil {
		return ""
	}
	return repo
}

// ParseImageRef splits an image reference into its fully qualified repository
// (docker.io/library/x for "x"), tag and digest, exactly as the guard reads it.
func ParseImageRef(ref string) (repo, tag, digest string, err error) { return parseRef(ref) }

// IsDigest reports whether s is a sha256 image digest as the guard accepts it.
func IsDigest(s string) bool { return digestRe.MatchString(s) }
