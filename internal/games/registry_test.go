package games

import "testing"

func TestNewRegistry(t *testing.T) {
	defs := []GameDef{
		{ID: "windrose", DisplayName: "Windrose"},
		{ID: "valheim", DisplayName: "Valheim"},
	}
	r, err := NewRegistry(defs)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	all := r.All()
	if len(all) != 2 || all[0].ID != "windrose" || all[1].ID != "valheim" {
		t.Fatalf("All() = %+v, want config order [windrose valheim]", all)
	}

	d, ok := r.Get("valheim")
	if !ok || d.DisplayName != "Valheim" {
		t.Fatalf("Get(valheim) = %+v, %v", d, ok)
	}

	if _, ok := r.Get("palworld"); ok {
		t.Fatal("Get(palworld) = true, want false for an unregistered id")
	}
}

func TestNewRegistry_MissingID(t *testing.T) {
	_, err := NewRegistry([]GameDef{{DisplayName: "No ID"}})
	if err == nil {
		t.Fatal("NewRegistry() error = nil, want error for missing ID")
	}
}

func TestNewRegistry_DuplicateID(t *testing.T) {
	defs := []GameDef{
		{ID: "windrose", DisplayName: "A"},
		{ID: "windrose", DisplayName: "B"},
	}
	_, err := NewRegistry(defs)
	if err == nil {
		t.Fatal("NewRegistry() error = nil, want error for duplicate id")
	}
}
