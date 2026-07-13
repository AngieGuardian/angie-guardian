// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package pow

import "sync"

var rotationMu sync.Mutex

func lockRotation(_ string) (func(), error) {
	rotationMu.Lock()
	return rotationMu.Unlock, nil
}
