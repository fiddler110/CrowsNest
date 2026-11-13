package modules

import (
	"strings"
	"testing"
)

func TestParseCatalogue(t *testing.T) {
	c, err := ParseCatalogue([]byte(`{"modules":[{"id":"a","name":"  A  ","url":"https://x.example/a/module.yaml","version":2}]}`))
	if err != nil || len(c.Modules) != 1 || c.Modules[0].Name != "A" || c.Modules[0].Version != 2 {
		t.Fatalf("got %+v, %v", c, err)
	}
	for name, in := range map[string]string{
		"not json":     `nope`,
		"bad id":       `{"modules":[{"id":"../x","url":"https://x.example/m.yaml"}]}`,
		"http":         `{"modules":[{"id":"a","url":"http://x.example/m.yaml"}]}`,
		"credentials":  `{"modules":[{"id":"a","url":"https://u:p@x.example/m.yaml"}]}`,
		"query":        `{"modules":[{"id":"a","url":"https://x.example/m.yaml?x=1"}]}`,
		"duplicate id": `{"modules":[{"id":"a","url":"https://x.example/1"},{"id":"a","url":"https://x.example/2"}]}`,
		"too many":     `{"modules":[` + strings.Repeat(`{"id":"a","url":"https://x.example/1"},`, 201) + `{"id":"b","url":"https://x.example/1"}]}`,
	} {
		if _, err := ParseCatalogue([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
