package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/straja-ai/straja-gateway/internal/server"
	"github.com/straja-ai/straja-gateway/internal/updater"
)

func runUpdateCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: straja update <check|apply> [flags]")
		return 2
	}
	switch args[0] {
	case "check":
		return runUpdateCheck(args[1:])
	case "apply":
		return runUpdateApply(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown update command %q\n", args[0])
		return 2
	}
}

func runUpdateCheck(args []string) int {
	fs := flag.NewFlagSet("update check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	client := updater.NewDefaultClient()
	check, err := client.Check(ctx, server.Version())
	if err != nil {
		fmt.Fprintf(os.Stderr, "update check failed: %v\n", err)
		return 1
	}

	fmt.Printf("Current version: %s\n", printableVersion(check.CurrentVersion))
	fmt.Printf("Latest version: %s\n", printableVersion(check.LatestVersion))
	switch {
	case !check.Comparable:
		fmt.Println("Update available: unknown (version format not comparable)")
	case check.UpdateAvailable:
		fmt.Println("Update available: yes")
	default:
		fmt.Println("Update available: no")
	}
	return 0
}

func runUpdateApply(args []string) int {
	fs := flag.NewFlagSet("update apply", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	targetVersion := fs.String("version", "", "Specific release tag to install (default: latest)")
	restart := fs.Bool("restart", false, "Restart gateway service after applying update")
	preserveConfig := fs.Bool("preserve-config", true, "Keep existing straja.yaml if present")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	current := server.Version()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client := updater.NewDefaultClient()
	result, err := client.Apply(ctx, updater.ApplyOptions{
		CurrentVersion: current,
		TargetVersion:  strings.TrimSpace(*targetVersion),
		PreserveConfig: *preserveConfig,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "update apply failed: %v\n", err)
		return 1
	}

	if !result.Applied {
		fmt.Printf("Already up to date (%s)\n", printableVersion(result.ToVersion))
		return 0
	}

	fmt.Printf("Updated Straja from %s to %s\n", printableVersion(result.FromVersion), printableVersion(result.ToVersion))
	fmt.Printf("Installed asset: %s\n", result.Asset)
	fmt.Printf("Install directory: %s\n", result.InstallDir)

	if !*restart {
		return 0
	}

	if err := restartGatewayService(); err != nil {
		fmt.Fprintf(os.Stderr, "update applied, but restart failed: %v\n", err)
		return 1
	}
	fmt.Println("Gateway service restarted")
	return 0
}

func printableVersion(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unknown"
	}
	return strings.TrimSpace(v)
}

type restartAttempt struct {
	bin  string
	args []string
}

func restartGatewayService() error {
	var attempts []restartAttempt
	switch runtime.GOOS {
	case "darwin":
		userID := currentUserID()
		attempts = append(attempts,
			restartAttempt{bin: "launchctl", args: []string{"kickstart", "-k", "system/ai.straja.gateway"}},
			restartAttempt{bin: "launchctl", args: []string{"kickstart", "-k", "gui/" + userID + "/ai.straja.gateway"}},
		)
	case "linux":
		attempts = append(attempts,
			restartAttempt{bin: "systemctl", args: []string{"restart", "straja"}},
			restartAttempt{bin: "systemctl", args: []string{"restart", "ai.straja.gateway"}},
		)
	default:
		return fmt.Errorf("automatic restart is not supported on %s", runtime.GOOS)
	}

	var failures []string
	for _, attempt := range attempts {
		if _, err := exec.LookPath(attempt.bin); err != nil {
			continue
		}
		cmd := exec.Command(attempt.bin, attempt.args...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		msg := fmt.Sprintf("%s %s failed: %v", attempt.bin, strings.Join(attempt.args, " "), err)
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			msg += " (" + trimmed + ")"
		}
		failures = append(failures, msg)
	}

	if len(failures) == 0 {
		return errors.New("no supported service manager command found (launchctl/systemctl)")
	}
	return errors.New(strings.Join(failures, "; "))
}

func currentUserID() string {
	u, err := user.Current()
	if err == nil {
		id := strings.TrimSpace(u.Uid)
		if id != "" {
			return id
		}
	}
	return "0"
}
