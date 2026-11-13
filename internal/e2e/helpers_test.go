package e2e

import (
	"lanora/internal/client/engine"
	"lanora/internal/server/hub"
	"lanora/internal/server/store"
)

type hubSession = hub.Session
type engineState = engine.State

func storePatchEnabled(enabled bool) store.RoomPatch { return store.RoomPatch{Enabled: &enabled} }
