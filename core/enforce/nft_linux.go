// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package enforce

import (
	"errors"
	"log/slog"
)

// newNFTSink constructs the kernel sink. Implemented in a follow-up commit on
// this branch; until then the sink reports unavailable and enforcement stays
// on the mirror + store paths.
func newNFTSink(NFTConfig, *slog.Logger) (Sink, error) {
	return nil, errors.New("nftables sink not implemented yet")
}
