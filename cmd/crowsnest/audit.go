package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/fiddler110/crowsnest/internal/audit"
	"github.com/fiddler110/crowsnest/internal/config"
)

const auditUsage = `usage:
  crowsnest audit verify [file]   check the audit file's hash chain (default: server.audit_file)
  crowsnest audit export [file]   write the audit file to standard output

verify says where the chain first breaks: an entry that was changed, removed, added or moved. It cannot see
entries cut off the end, so keep the last hash it prints somewhere else and compare next time.`

func runAudit(args []string, out io.Writer) error {
	if len(args) == 0 || len(args) > 2 || (args[0] != "verify" && args[0] != "export") {
		return errors.New(auditUsage)
	}
	var path string
	if len(args) == 2 {
		path = args[1]
	} else {
		cfg, err := config.Load(configPath())
		if err != nil {
			return fmt.Errorf("config does not load: %w", err)
		}
		path = cfg.Server.AuditFile
	}
	if args[0] == "export" {
		f, err := os.Open(path) // #nosec G304 -- chosen by the operator
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(out, f)
		return err
	}
	n, last, err := audit.Verify(path)
	if err != nil {
		if n > 0 || !os.IsNotExist(err) {
			return fmt.Errorf("%s: BROKEN after %d good entries: %w", path, n, err)
		}
		return err
	}
	if n == 0 {
		fmt.Fprintf(out, "%s: empty\n", path)
		return nil
	}
	fmt.Fprintf(out, "%s: OK, %d entries\nlast hash: %s\n", path, n, last)
	return nil
}
