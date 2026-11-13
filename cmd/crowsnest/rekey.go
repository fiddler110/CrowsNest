package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/managed"
	"github.com/fiddler110/crowsnest/internal/mfa"
	"github.com/fiddler110/crowsnest/internal/vault"
)

// NewKeyEnv names the variable that holds the master key to move to.
const NewKeyEnv = "CROWSNEST_NEW_MASTER_KEY"

const rekeyUsage = `usage: crowsnest rekey

Re-encrypts every sealed file (the session secret, Google and SSO client secrets, authenticator apps, the dashboard
games' passwords) under a new master key, or, with no new key, under the current key's newest scheme.

  1. Stop the panel.
  2. Take a snapshot first:  crowsnest state export
  3. Give the current key as usual (CROWSNEST_MASTER_KEY, or the master.key file) and the new one in ` + NewKeyEnv + `
     (at least 24 characters; try ` + "`openssl rand -base64 32`" + `):
         CROWSNEST_NEW_MASTER_KEY=... crowsnest rekey
  4. Set CROWSNEST_MASTER_KEY to the new value, remove ` + NewKeyEnv + `, delete master.key if you used one, start the panel.

It is safe to run again if it was interrupted. Anything the old key cannot open stops it with a message.`

func runRekey(out io.Writer) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("config does not load: %w", err)
	}
	keyFile := filepath.Join(filepath.Dir(cfg.Server.SessionSecretFile), "master.key")
	if _, err := os.Stat(keyFile); os.Getenv(vault.EnvKey) == "" && err != nil {
		return fmt.Errorf("there is no current master key: %s is not set and %s does not exist, so nothing is sealed yet", vault.EnvKey, keyFile)
	}
	from, err := vault.New(os.Getenv(vault.EnvKey), keyFile)
	if err != nil {
		return err
	}
	to := from
	if nk := os.Getenv(NewKeyEnv); nk != "" {
		if to, err = vault.New(nk, ""); err != nil {
			return fmt.Errorf("%s: %w", NewKeyEnv, err)
		}
	}
	settingsDir := filepath.Dir(cfg.Server.SettingsFile)
	type job struct {
		name string
		run  func() (int, error)
	}
	jobs := []job{
		{"session secret", func() (int, error) { return auth.ResealSessionSecret(cfg.Server.SessionSecretFile, from, to) }},
		{"Google sign-in secret", func() (int, error) { return auth.ResealGoogleConf(filepath.Join(settingsDir, "auth.json"), from, to) }},
		{"SSO client secrets", func() (int, error) { return auth.ResealOIDC(filepath.Join(settingsDir, "oidc.json"), from, to) }},
		{"authenticator apps", func() (int, error) { return mfa.Reseal(filepath.Join(settingsDir, "mfa.json"), from, to) }},
	}
	if cfg.Managed.Dir != "" {
		jobs = append(jobs, job{"dashboard game secrets", func() (int, error) {
			return managed.ResealSecrets(filepath.Join(cfg.Managed.Dir, "secrets.json"), from, to)
		}})
	}
	total := 0
	for _, j := range jobs {
		n, err := j.run()
		if err != nil {
			return fmt.Errorf("%s: %w\n(nothing after this was changed; fix the cause and run it again)", j.name, err)
		}
		fmt.Fprintf(out, "%-24s %d re-sealed\n", j.name, n)
		total += n
	}
	if from == to {
		fmt.Fprintf(out, "\nDone: %d values now use the current scheme under the same key.\n", total)
		return nil
	}
	if from.Source == vault.SourceFile {
		fmt.Fprintf(out, "\nDone: %d values moved to the new key. The old key was the file %s: delete it once the panel starts with the new one.\n", total, keyFile)
	} else {
		fmt.Fprintf(out, "\nDone: %d values moved to the new key.\n", total)
	}
	fmt.Fprintf(out, "Now set %s to the new value, remove %s, and start the panel.\n", vault.EnvKey, NewKeyEnv)
	return nil
}

var errRekeyUsage = errors.New(rekeyUsage)
