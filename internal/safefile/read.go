// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package safefile provides bounded reads for operator-managed artifacts.
package safefile

import (
	"fmt"
	"io"
	"os"
)

// Read returns at most max bytes. It checks both metadata and the actual read
// so a concurrently replaced or growing file cannot bypass the limit.
func Read(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil {
		return nil, err
	} else if st.Size() > max {
		return nil, fmt.Errorf("%s exceeds the %d-byte size limit", path, max)
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s exceeds the %d-byte size limit", path, max)
	}
	return raw, nil
}
