package server

import (
	"net/http"

	"github.com/Autumn-27/artex/agent"
)

func (s *Server) pgToolsInventory(w http.ResponseWriter, r *http.Request) {
	items := agent.ProbeToolInventory()
	writeJSON(w, http.StatusOK, map[string]any{
		"tools": items,
	})
}
