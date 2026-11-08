package dockerguard

import (
	"fmt"
	"math"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"
)

// denial is a refusal with the HTTP status the client sees.
type denial struct {
	status int
	msg    string
}

func (d *denial) Error() string { return d.msg }

func deny(status int, format string, args ...any) error {
	return &denial{status: status, msg: fmt.Sprintf(format, args...)}
}

// rule checks one value; nil means "anything". ruleEmpty and ruleNull are the
// two shared sentinels of checkObject.
type rule func(v any, name string) error

func ruleEmpty(v any, name string) error {
	if !isEmpty(v) {
		return deny(403, "%s is not allowed", name)
	}
	return nil
}

func ruleNull(v any, name string) error {
	if v != nil {
		return deny(403, "%s may not be set (not even to an empty list)", name)
	}
	return nil
}

// checkObject requires every key of obj to be in rules (a rule, or nil for
// "anything") or, unknown, to hold a plain null/false/0/"". Keys are matched
// exactly; a different spelling of a known key ("privileged", "Mountſ") is
// refused, because the engine would read it as the known field. A null obj is
// an empty one; anything else that is not an object is refused.
func checkObject(obj any, rules map[string]rule, where string) (map[string]any, error) {
	if obj == nil {
		return map[string]any{}, nil
	}
	m, ok := obj.(map[string]any)
	if !ok {
		return nil, deny(400, "%s must be an object", where)
	}
	folded := make(map[string]bool, len(rules))
	for k := range rules {
		folded[foldKey(k)] = true
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // a stable message when several keys are wrong
	for _, key := range keys {
		value := m[key]
		name := where + "." + key
		if r, known := rules[key]; known {
			if r != nil {
				if err := r(value, name); err != nil {
					return nil, err
				}
			}
			continue
		}
		if !isASCII(key) || folded[foldKey(key)] {
			return nil, deny(403, "%s: unexpected spelling of a known field", quote(name))
		}
		if !scalarEmpty(value) {
			return nil, deny(403, "%s is not allowed", quote(name))
		}
	}
	return m, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// ---- rule library

// isKind accepts values of the given kinds that pass test.
func isKind(kinds kind, test func(any) bool, msg string) rule {
	return func(v any, name string) error {
		if kindOf(v)&kinds == 0 || (test != nil && !test(v)) {
			return deny(403, "%s %s", name, msg)
		}
		return nil
	}
}

const badValue = "has a bad value"

func oneOf(choices ...string) rule {
	return isKind(kStr, func(v any) bool {
		s := v.(string)
		for _, c := range choices {
			if s == c {
				return true
			}
		}
		return false
	}, fmt.Sprintf("must be one of %s", strings.Join(choices, ", ")))
}

func intMin(lo int64, hi ...int64) rule {
	max := int64(math.MaxInt64)
	if len(hi) > 0 {
		max = hi[0]
	}
	return isKind(kNull|kInt, func(v any) bool {
		if v == nil {
			return true
		}
		n, _ := asInt(v)
		return n >= lo && n <= max
	}, badValue)
}

var (
	ruleBool    = isKind(kNull|kBool, nil, badValue)
	ruleStr     = isKind(kNull|kStr, nil, badValue)
	ruleList    = isKind(kNull|kList, nil, badValue)
	ruleStrings = isKind(kNull|kList, func(v any) bool {
		list, _ := v.([]any)
		for _, x := range list {
			if _, ok := x.(string); !ok {
				return false
			}
		}
		return true
	}, "must be a list of strings")
	ruleStringMap = isKind(kNull|kDict, func(v any) bool {
		m, _ := v.(map[string]any)
		for _, x := range m {
			if _, ok := x.(string); !ok {
				return false
			}
		}
		return true
	}, "must map to strings")
)

func objectRule(rules map[string]rule) rule {
	return func(v any, name string) error {
		_, err := checkObject(v, rules, name)
		return err
	}
}

// ---- create bodies

func bindSource(s *Scope, src any, name string) error {
	str, ok := src.(string)
	if !ok || !strings.HasPrefix(str, "/") || path.Clean(str) != str || strings.ContainsRune(str, 0) {
		return deny(403, "%s: bind source %s must be an absolute, normalised path", name, quote(src))
	}
	if !s.bindOK(str) {
		return deny(403, "%s: bind source %s is not one of %s's paths", name, quote(str), s.Name)
	}
	return nil
}

var volumeNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`)

func volumeName(s *Scope, vol any, name string) error {
	str, ok := vol.(string)
	if !ok || !volumeNameRe.MatchString(str) {
		return deny(403, "%s: bad volume name %s", name, quote(vol))
	}
	if !s.volumeOK(str) {
		return deny(403, "%s: volume %s is not one of %s's volumes", name, quote(str), s.Name)
	}
	return nil
}

var bindModes = map[string]bool{"ro": true, "rw": true, "z": true, "Z": true, "nocopy": true, "private": true, "rprivate": true,
	"consistent": true, "cached": true, "delegated": true}

func bindsRule(s *Scope) rule {
	return func(v any, name string) error {
		if err := ruleStrings(v, name); err != nil {
			return err
		}
		list, _ := v.([]any)
		for _, item := range list {
			b := item.(string)
			parts := strings.Split(b, ":")
			if (len(parts) != 2 && len(parts) != 3) || !strings.HasPrefix(parts[1], "/") {
				return deny(403, "%s: %s is not source:/target[:options]", name, quote(b))
			}
			if len(parts) == 3 {
				for _, o := range strings.Split(parts[2], ",") {
					if !bindModes[o] {
						return deny(403, "%s: bind option %s is not allowed", name, quote(o))
					}
				}
			}
			var err error
			if strings.HasPrefix(parts[0], "/") {
				err = bindSource(s, parts[0], name)
			} else {
				err = volumeName(s, parts[0], name)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
}

var (
	bindOptionRules = map[string]rule{
		"Propagation": isKind(kNull|kStr, func(v any) bool {
			s, _ := v.(string)
			return s == "" || s == "private" || s == "rprivate"
		}, "must be private"),
		"NonRecursive": ruleBool, "CreateMountpoint": ruleBool, "ReadOnlyNonRecursive": ruleBool, "ReadOnlyForceRecursive": ruleBool}
	driverConfigRules = map[string]rule{
		"Name": isKind(kNull|kStr, func(v any) bool {
			s, _ := v.(string)
			return s == "" || s == "local"
		}, "must be the local driver"),
		"Options": ruleEmpty}
	volumeOptionRules = map[string]rule{
		"NoCopy": ruleBool, "Labels": ruleStringMap, "DriverConfig": objectRule(driverConfigRules),
		"Subpath": isKind(kNull|kStr, func(v any) bool {
			s, _ := v.(string)
			if s == "" {
				return true
			}
			if strings.HasPrefix(s, "/") {
				return false
			}
			for _, seg := range strings.Split(s, "/") {
				if seg == ".." {
					return false
				}
			}
			return true
		}, badValue)}
	tmpfsOptionRules = map[string]rule{"SizeBytes": intMin(0), "Mode": intMin(0, 0o7777), "Options": ruleList}
)

func absPath(v any, name string) error {
	return isKind(kStr, func(v any) bool { return strings.HasPrefix(v.(string), "/") }, "must be an absolute path")(v, name)
}

func mountsRule(s *Scope) rule {
	return func(v any, name string) error {
		if v == nil {
			return nil
		}
		list, ok := v.([]any)
		if !ok {
			return deny(400, "%s must be a list", name)
		}
		for i, item := range list {
			where := fmt.Sprintf("%s[%d]", name, i)
			m, _ := item.(map[string]any)
			typ, _ := m["Type"].(string)
			if typ != "bind" && typ != "volume" && typ != "tmpfs" {
				return deny(403, "%s: mount type %s is not allowed", where, quote(m["Type"]))
			}
			rules := map[string]rule{
				"Type": nil, "Source": nil, "Target": absPath, "ReadOnly": ruleBool, "Consistency": ruleStr,
				"BindOptions": ruleEmpty, "VolumeOptions": ruleEmpty, "TmpfsOptions": ruleEmpty,
			}
			switch typ {
			case "bind":
				rules["BindOptions"] = objectRule(bindOptionRules)
			case "volume":
				rules["VolumeOptions"] = objectRule(volumeOptionRules)
			case "tmpfs":
				rules["TmpfsOptions"] = objectRule(tmpfsOptionRules)
			}
			if _, err := checkObject(item, rules, where); err != nil {
				return err
			}
			src := m["Source"]
			switch typ {
			case "bind":
				if err := bindSource(s, src, where); err != nil {
					return err
				}
			case "volume":
				// no source: an anonymous volume, local driver, nothing shared
				switch t := src.(type) {
				case nil:
				case string:
					if t != "" {
						if err := volumeName(s, t, where); err != nil {
							return err
						}
					}
				default:
					return deny(403, "%s: bad volume name %s", where, quote(src))
				}
			case "tmpfs":
				if t, isStr := src.(string); src != nil && (!isStr || t != "") {
					return deny(403, "%s: a tmpfs has no source", where)
				}
			}
		}
		return nil
	}
}

var portKeyRe = regexp.MustCompile(`^([0-9]+(?:-[0-9]+)?)(?:/(tcp|udp|sctp))?$`)

func portBindingsRule(s *Scope) rule {
	return func(v any, name string) error {
		if v == nil {
			return nil
		}
		m, ok := v.(map[string]any)
		if !ok {
			return deny(400, "%s must be an object", name)
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			mm := portKeyRe.FindStringSubmatch(key)
			if mm == nil {
				return deny(403, "%s: bad port %s", name, quote(key))
			}
			containerPort, proto := mm[1], mm[2]
			if proto == "" {
				proto = "tcp"
			}
			bindings := m[key]
			if bindings != nil {
				if _, isList := bindings.([]any); !isList {
					return deny(400, "%s[%s] must be a list", name, key)
				}
			}
			list, _ := bindings.([]any)
			for _, b := range list {
				bm, isObj := b.(map[string]any)
				if !isObj {
					return deny(400, "%s[%s]: a binding is an object", name, key)
				}
				if _, err := checkObject(bm, map[string]rule{"HostIp": ruleStr, "HostPort": ruleStr}, fmt.Sprintf("%s[%s]", name, key)); err != nil {
					return err
				}
				ip, _ := bm["HostIp"].(string)
				port, _ := bm["HostPort"].(string) // "" is every interface / a random port, as the engine reads it
				if ip == "" {
					ip = "0.0.0.0"
				}
				addr, err := netip.ParseAddr(ip)
				if err != nil || addr.Zone() != "" {
					return deny(403, "%s[%s]: bad host address %s", name, key, quote(ip))
				}
				ip = addr.String()
				allowed := false
				for _, p := range s.Ports {
					if p.HostIP == ip && p.HostPort == port && p.Proto == proto && (p.ContainerPort == "" || p.ContainerPort == containerPort) {
						allowed = true
						break
					}
				}
				if !allowed {
					shown := port
					if shown == "" {
						shown = "<any>"
					}
					return deny(403, "%s: publishing %s:%s->%s is not allowed for %s", name, ip, quote(shown), quote(key), s.Name)
				}
			}
		}
		return nil
	}
}

func securityOptsRule(s *Scope) rule {
	return func(v any, name string) error {
		if err := ruleStrings(v, name); err != nil {
			return err
		}
		list, _ := v.([]any)
		for _, item := range list {
			opt := item.(string)
			switch opt {
			case "no-new-privileges", "no-new-privileges:true", "no-new-privileges=true":
				continue
			}
			if !s.SecOpts[opt] {
				short := strings.SplitN(strings.SplitN(opt, "=", 2)[0], ":", 2)[0]
				return deny(403, "%s: security option %s is not allowed for %s", name, quote(short), s.Name)
			}
		}
		return nil
	}
}

func capAddRule(s *Scope) rule {
	return func(v any, name string) error {
		if err := ruleStrings(v, name); err != nil {
			return err
		}
		list, _ := v.([]any)
		for _, item := range list {
			if c := normCap(item); c == "" || !s.CapAdd[c] {
				return deny(403, "%s: capability %s is not allowed for %s", name, quote(item), s.Name)
			}
		}
		return nil
	}
}

var ulimitRules = map[string]rule{"Name": oneOf("nofile", "nproc"), "Soft": intMin(-1), "Hard": intMin(-1)}

func ulimitsRule(v any, name string) error {
	if v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return deny(400, "%s must be a list", name)
	}
	for _, u := range list {
		if u == nil { // the engine reads a null entry as a nil pointer
			return deny(403, "%s: a null entry is not allowed", name)
		}
		if _, err := checkObject(u, ulimitRules, name); err != nil {
			return err
		}
	}
	return nil
}

var (
	restartRules = map[string]rule{"Name": oneOf("", "no", "always", "unless-stopped", "on-failure"), "MaximumRetryCount": intMin(0)}
	logRules     = map[string]rule{"Type": oneOf("", "json-file", "local", "none"), "Config": ruleStringMap}
)

// hostConfigRules lists every HostConfig field a compose service (or docker
// run) can send, and what a scope may put in it. Unknown fields must be empty
// scalars, so a field the engine gains later is refused until someone decides
// about it here.
func hostConfigRules(s *Scope) map[string]rule {
	r := map[string]rule{
		// checked against the scope
		"Binds": bindsRule(s), "Mounts": mountsRule(s), "PortBindings": portBindingsRule(s),
		"NetworkMode": nil, // checked together with NetworkingConfig
		"SecurityOpt": securityOptsRule(s), "CapAdd": capAddRule(s),
		// limits and behaviour that stay inside the container's own cgroup and namespaces
		"RestartPolicy": objectRule(restartRules), "LogConfig": objectRule(logRules),
		"Memory": intMin(0), "MemorySwap": intMin(-1), "MemoryReservation": intMin(0),
		"MemorySwappiness": intMin(-1, 100), "NanoCpus": intMin(0), "CpuShares": intMin(0), "CpuPeriod": intMin(0),
		"CpuQuota": intMin(-1), "CpusetCpus": ruleStr, "CpusetMems": ruleStr, "BlkioWeight": intMin(0, 1000),
		"PidsLimit": intMin(-1), "Ulimits": ulimitsRule, "Init": ruleBool, "ShmSize": intMin(0),
		"OomScoreAdj": intMin(0, 1000), // negative would protect the game at the expense of everything else
		"ExtraHosts":  ruleStrings, "Dns": ruleStrings, "DnsOptions": ruleStrings, "DnsSearch": ruleStrings, "CapDrop": ruleStrings,
		"ReadonlyRootfs": ruleBool, "Tmpfs": ruleStringMap,
		"IpcMode": oneOf("", "private", "shareable", "none"), "CgroupnsMode": oneOf("", "private"),
		"Isolation": oneOf("", "default"), "ConsoleSize": ruleList,
		// null means the engine's default masks; [] would unmask /proc/kcore, /sys/firmware and the rest
		"MaskedPaths": ruleNull, "ReadonlyPaths": ruleNull,
	}
	// host access: always empty / unset. AutoRemove too: an auto-removed
	// container can't be inspected after the fact.
	for _, k := range []string{"AutoRemove", "Privileged", "PublishAllPorts", "VolumesFrom", "VolumeDriver", "Links", "Devices",
		"DeviceCgroupRules", "DeviceRequests", "GroupAdd", "Sysctls", "PidMode", "UTSMode", "UsernsMode", "Cgroup", "CgroupParent",
		"Runtime", "StorageOpt", "Annotations", "ContainerIDFile", "OomKillDisable", "CpuRealtimePeriod", "CpuRealtimeRuntime",
		"CpuCount", "CpuPercent", "BlkioWeightDevice", "BlkioDeviceReadBps", "BlkioDeviceWriteBps", "BlkioDeviceReadIOps",
		"BlkioDeviceWriteIOps", "IOMaximumIOps", "IOMaximumBandwidth", "KernelMemory", "KernelMemoryTCP"} {
		r[k] = ruleEmpty
	}
	return r
}

// ipamRules: compose sends these empty for "no fixed address". IPv4Address may
// also be one of the addresses the scope pins for this network (Scope.IPv4).
func ipamRules(s *Scope, network string) map[string]rule {
	return map[string]rule{"IPv4Address": ipv4Rule(s, network), "IPv6Address": ruleEmpty, "LinkLocalIPs": ruleEmpty}
}

func ipv4Rule(s *Scope, network string) rule {
	return func(v any, name string) error {
		if isEmpty(v) {
			return nil
		}
		str, _ := v.(string)
		for _, a := range s.IPv4[network] {
			if str == a {
				return nil
			}
		}
		return deny(403, "%s: address %s is not allowed for %s on this network", name, quote(v), s.Name)
	}
}

// aliasesRule: names other containers on the network resolve to this one are
// the scope's own name (compose adds the container name and the service name)
// and the scope's listed aliases - never another service's name, which would
// take over its traffic.
func aliasesRule(s *Scope) rule {
	return func(v any, name string) error {
		if err := ruleStrings(v, name); err != nil {
			return err
		}
		list, _ := v.([]any)
		for _, item := range list {
			a := item.(string)
			if a != s.Name && !s.Aliases[a] {
				return deny(403, "%s: network alias %s is not allowed for %s", name, quote(a), s.Name)
			}
		}
		return nil
	}
}

// endpointRules checks one network attachment; network is the resolved name of
// the network (not an id), which selects the scope's pinned addresses.
func endpointRules(s *Scope, network string) map[string]rule {
	return map[string]rule{"Aliases": aliasesRule(s), "DNSNames": aliasesRule(s), "GwPriority": intMin(-(1 << 31)),
		"IPAMConfig": objectRule(ipamRules(s, network)),
		"Links":      ruleEmpty, "DriverOpts": ruleEmpty, "MacAddress": ruleEmpty, // DriverOpts can set sysctls
		"NetworkID": ruleEmpty, "EndpointID": ruleEmpty, "Gateway": ruleEmpty, "IPAddress": ruleEmpty, "IPPrefixLen": ruleEmpty,
		"IPv6Gateway": ruleEmpty, "GlobalIPv6Address": ruleEmpty, "GlobalIPv6PrefixLen": ruleEmpty}
}

// labelsRule: compose's own com.docker.compose.* bookkeeping, and the scope's
// exact label: value pairs. Other labels are how other containers (a reverse
// proxy, a job runner, an updater) take instructions, so a scope client may
// not set them.
func labelsRule(s *Scope) rule {
	return func(v any, name string) error {
		if err := ruleStringMap(v, name); err != nil {
			return err
		}
		m, _ := v.(map[string]any)
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			want, listed := s.Labels[k]
			if !strings.HasPrefix(k, "com.docker.compose.") && !(listed && want == m[k].(string)) {
				return deny(403, "%s: label %s is not allowed for %s", name, quote(k), s.Name)
			}
		}
		return nil
	}
}

// configRules are the container's own settings: compose sets them all. They
// act inside the container, so they are free; the image allow-list is what
// bounds the code that runs, and HostConfig what it can reach.
func configRules(s *Scope) map[string]rule {
	r := map[string]rule{}
	for _, k := range []string{"Hostname", "Domainname", "User", "AttachStdin", "AttachStdout", "AttachStderr", "ExposedPorts", "Tty",
		"OpenStdin", "StdinOnce", "Env", "Cmd", "Healthcheck", "ArgsEscaped", "WorkingDir", "Entrypoint", "NetworkDisabled",
		"OnBuild", "StopSignal", "StopTimeout", "Shell"} {
		r[k] = nil
	}
	r["MacAddress"] = ruleEmpty
	r["Volumes"] = isKind(kNull|kDict, func(v any) bool {
		m, _ := v.(map[string]any)
		for k := range m {
			if !strings.HasPrefix(k, "/") || strings.Contains(k, ":") {
				return false
			}
		}
		return true
	}, "must name container paths (anonymous volumes)")
	r["Labels"] = labelsRule(s)
	r["Image"] = nil
	r["HostConfig"] = nil
	r["NetworkingConfig"] = nil
	return r
}

var execBodyRules = map[string]rule{
	"User":       isKind(kNull|kStr, func(v any) bool { s, _ := v.(string); return s == "" }, "must be empty (the image's own user)"),
	"Privileged": ruleEmpty, "Tty": ruleBool, "AttachStdin": ruleBool, "AttachStdout": ruleBool, "AttachStderr": ruleBool,
	"DetachKeys": ruleStr, "Env": ruleStrings, "WorkingDir": ruleStr,
	"Cmd": isKind(kList, func(v any) bool {
		list, _ := v.([]any)
		if len(list) == 0 {
			return false
		}
		for _, x := range list {
			if _, ok := x.(string); !ok {
				return false
			}
		}
		return true
	}, "must be a command"),
	"ConsoleSize": ruleList,
}

var execStartRules = map[string]rule{"Detach": ruleBool, "Tty": ruleBool, "ConsoleSize": ruleList}
