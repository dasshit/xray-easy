package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"xray-easy/internal/lease"
)

// validateLeaseConfiguration checks enabled lease policy values before Compose
// starts so a bad duration cannot leave the optional service unhealthy.
func validateLeaseConfiguration(root string, cfg configuration) error {
	if !cfg.leaseEnabled {
		return nil
	}
	values := map[string]string{}
	if _, err := os.Stat(filepath.Join(root, ".env")); err == nil {
		loaded, readErr := readEnvironmentFile(filepath.Join(root, ".env"))
		if readErr != nil {
			return readErr
		}
		values = loaded
	} else if !os.IsNotExist(err) {
		return err
	}
	maxActive := 2
	if value := values["XRAY_LEASE_MAX_ACTIVE"]; value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("XRAY_LEASE_MAX_ACTIVE: %w", err)
		}
		maxActive = parsed
	}
	grace, err := leaseDuration(values["XRAY_LEASE_GRACE"], 30*time.Second)
	if err != nil {
		return fmt.Errorf("XRAY_LEASE_GRACE: %w", err)
	}
	retry, err := leaseDuration(values["XRAY_LEASE_RETRY_DELAY"], time.Second)
	if err != nil {
		return fmt.Errorf("XRAY_LEASE_RETRY_DELAY: %w", err)
	}
	config := lease.Config{MaxActiveLeases: maxActive, GracePeriod: grace, RetryDelay: retry}
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid Xray lease policy: %w", err)
	}
	return nil
}

// leaseDuration parses a configured duration or returns its default value.
func leaseDuration(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	return time.ParseDuration(value)
}
