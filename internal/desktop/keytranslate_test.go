//go:build windows && (amd64 || arm64)

package desktop

import "testing"

func TestTranslateKey(t *testing.T) {
	cases := []struct {
		name        string
		vk          uint32
		shift, caps bool
		wantRune    rune
		wantPrint   bool
		wantName    string
	}{
		{"lowercase letter", 'A', false, false, 'a', true, ""},
		{"shift upper", 'A', true, false, 'A', true, ""},
		{"caps upper", 'A', false, true, 'A', true, ""},
		{"shift and caps cancel", 'A', true, true, 'a', true, ""},
		{"digit", '1', false, false, '1', true, ""},
		{"shifted digit is a symbol", '1', true, false, '!', true, ""},
		{"oem semicolon", 0xBA, false, false, ';', true, ""},
		{"shifted oem semicolon", 0xBA, true, false, ':', true, ""},
		{"space", 0x20, false, false, ' ', true, ""},
		{"enter is a named key", 0x0D, false, false, 0, false, "Enter"},
		{"tab is a named key", 0x09, false, false, 0, false, "Tab"},
		{"shift alone is ignored", 0x10, false, false, 0, false, ""},
		{"the stop key F9 is never emitted", 0x78, false, false, 0, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, printable, name := translateKey(c.vk, c.shift, c.caps)
			if r != c.wantRune || printable != c.wantPrint || name != c.wantName {
				t.Errorf("translateKey(%#x, shift=%v, caps=%v) = (%q, %v, %q), want (%q, %v, %q)",
					c.vk, c.shift, c.caps, r, printable, name, c.wantRune, c.wantPrint, c.wantName)
			}
		})
	}
}
