package web

import (
	"encoding/json"
	"net/http"
	"sort"
)

type mentionGame struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Checked bool   `json:"checked"`
}

type mentionView struct {
	Available bool          `json:"available"` // false when Discord isn't set up, so there is nothing to ping on
	DiscordID string        `json:"discord_id"`
	Games     []mentionGame `json:"games"`
}

// handleGetMentions shows the caller's Discord id and which of the games they may see they have chosen.
func (a *App) handleGetMentions(w http.ResponseWriter, r *http.Request) {
	m := a.Mentions.Get(actor(r))
	chosen := map[string]bool{}
	for _, g := range m.Games {
		chosen[g] = true
	}
	v := mentionView{Available: a.Mentions != nil && a.DiscordOn, DiscordID: m.DiscordID, Games: []mentionGame{}}
	for _, d := range a.visibleGames(r) {
		v.Games = append(v.Games, mentionGame{ID: d.ID, Name: d.DisplayName, Checked: chosen[d.ID]})
	}
	sort.Slice(v.Games, func(i, j int) bool { return v.Games[i].Name < v.Games[j].Name })
	writeJSON(w, http.StatusOK, v)
}

// handlePutMentions saves the caller's Discord id and games. Only games they may see are kept.
func (a *App) handlePutMentions(w http.ResponseWriter, r *http.Request) {
	if a.Mentions == nil {
		http.NotFound(w, r)
		return
	}
	var body struct {
		DiscordID string   `json:"discord_id"`
		Games     []string `json:"games"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	visible := map[string]bool{}
	for _, d := range a.visibleGames(r) {
		visible[d.ID] = true
	}
	if err := a.Mentions.Set(actor(r), body.DiscordID, body.Games, func(id string) bool { return visible[id] }); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.handleGetMentions(w, r)
}
