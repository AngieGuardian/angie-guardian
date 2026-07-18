// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package enforce

import (
	"errors"
	"log/slog"
)

// newNFTSink is the non-Linux stub. Config validation refuses
// enforcement.nftables.enabled off Linux, so this is unreachable in practice
// and exists to keep the package portable.
func newNFTSink(NFTConfig, *slog.Logger) (Sink, error) {
	return nil, errors.New("nftables enforcement requires Linux")
}
