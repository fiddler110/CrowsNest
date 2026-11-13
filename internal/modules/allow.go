package modules

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fiddler110/crowsnest/internal/dockerguard"
)

// SignedAllowances is what the guard takes from allowed modules that were installed from a URL. A module counts only
// if its module.yaml in dir carries a valid signature (module.yaml.sig, kept when it was installed) from one of the
// policy's trusted keys, and its manifest has the id it is filed under. For each it returns the image repository and
// the ports the manifest declares. Anything else is a problem, not an allowance: the panel can write these files,
// so the signature, checked again here against keys only the operator can change, is the whole basis for trust.
// Bundled ids are skipped: their ports are compiled in.
func SignedAllowances(dir string, allowed []string, policyKeys []dockerguard.PolicyKey) (images []string, ports map[string][]string, problems []error) {
	ports = map[string][]string{}
	var in []TrustedKey
	for _, k := range policyKeys {
		in = append(in, TrustedKey{Name: k.Name, Key: k.PublicKey})
	}
	keys, err := ParseTrustedKeys(in)
	if err != nil {
		return nil, ports, []error{fmt.Errorf("policy trusted_keys: %w", err)}
	}
	bundled := Bundled().IDs()
	for _, id := range allowed {
		if slices.Contains(bundled, id) {
			continue
		}
		fail := func(why string) {
			problems = append(problems, fmt.Errorf("module %s is switched on but the guard cannot admit it: %s", id, why))
		}
		if dir == "" || !idRe.MatchString(id) {
			fail("no modules folder is configured for the guard")
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, id, "module.yaml")) // #nosec G304 -- id matches idRe
		if err != nil {
			fail("its module.yaml cannot be read")
			continue
		}
		sig, err := os.ReadFile(filepath.Join(dir, id, "module.yaml"+SigSuffix)) // #nosec G304 -- id matches idRe
		if err != nil {
			fail("it has no saved signature (install it again from a signed source)")
			continue
		}
		if _, err := VerifySignature(keys, body, sig); err != nil {
			fail("no key in policy.yaml trusted_keys signed this copy")
			continue
		}
		m, err := Parse(bytes.NewReader(body))
		if err != nil || m.ID != id {
			fail("its manifest does not parse or has another id")
			continue
		}
		if m.Runtime.Image != "" {
			repo, _, _, err := dockerguard.ParseImageRef(m.Runtime.Image)
			if err != nil {
				fail("its image is not a valid reference")
				continue
			}
			images = append(images, repo)
		}
		for _, p := range m.Runtime.Ports {
			ports[id] = append(ports[id], PortSpec(p))
		}
	}
	return images, ports, problems
}

// SignedFunc is SignedAllowances for the modules folder dir, in the shape the policy loader takes.
func SignedFunc(dir string) dockerguard.SignedFunc {
	return func(allowed []string, keys []dockerguard.PolicyKey) ([]string, map[string][]string, []error) {
		return SignedAllowances(dir, allowed, keys)
	}
}

// ModuleSigned reports whether id is installed from a URL with a saved signature that one of keys made, without
// reading anything the guard would not.
func ModuleSigned(dir, id string, keys []dockerguard.PolicyKey) bool {
	if len(keys) == 0 {
		return false
	}
	_, _, problems := SignedAllowances(dir, []string{id}, keys)
	return len(problems) == 0 && !strings.Contains(id, "/")
}
