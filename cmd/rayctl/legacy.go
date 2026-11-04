package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/arngory/raycontrol/internal/legacy"
)

// legacyCmd finds raycontrol v0 (legacy/ray.sh) and, with -remove, backs
// it up and takes away what it installed (docs/08-decisions.md, R4-26).
// No rayd is needed: the bootstrap runs it before the install.
func (c *cli) legacyCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("legacy", flag.ContinueOnError)
	remove := fs.Bool("remove", false, "back raycontrol v0 up, then remove what it installed")
	yes := fs.Bool("yes", false, "do not ask")
	purge := fs.Bool("purge-packages", false, "also purge the packages only v0 needed: certbot (unless other certificates are there), PostgreSQL (unless other databases are), qrencode")
	backupDir := fs.String("backup-dir", "/root", "directory for the backup")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	h := legacy.System(os.Stdout)
	found := h.Detect(ctx)
	if !found.Any() {
		fmt.Println("no raycontrol v0 (ray.sh) on this host")
		return nil
	}
	fmt.Println("raycontrol v0 (ray.sh) is installed:")
	for _, it := range found.Items {
		fmt.Println("  " + it)
	}
	for _, k := range found.Kept {
		fmt.Println("  stays: " + k)
	}
	if !*remove {
		fmt.Println("rayctl legacy -remove backs these up, then removes them; nothing else is touched")
		return nil
	}
	if err := needRoot(); err != nil {
		return err
	}
	if !*yes {
		fmt.Print("This stops v0's services, removes its firewall table, database, certificate and files (a backup first). Type yes to go on: ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(answer) != "yes" {
			return errors.New("not confirmed")
		}
	}
	name, err := h.Backup(ctx, found, *backupDir)
	if err != nil {
		return fmt.Errorf("backup failed, nothing removed: %w", err)
	}
	fmt.Printf("backup: %s (v0's settings, secrets and users: keep it safe, delete it when you no longer need it)\n", name)
	if err := h.Remove(ctx, found, *purge); err != nil {
		return fmt.Errorf("raycontrol v0 removed in part: %w", err)
	}
	fmt.Println("raycontrol v0 removed")
	return nil
}
