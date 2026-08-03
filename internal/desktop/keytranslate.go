//go:build windows && (amd64 || arm64)

package desktop

// translateKey maps a virtual-key code plus the shift/caps state to either a
// printable character or a named key. It is a deliberately self-contained,
// pure function — no Win32 calls — so it is unit-testable, and it avoids the
// dead-key kernel-state hazards of ToUnicode. It targets the US layout; other
// layouts fall back to the base character or a named key.
//
// It returns (r, true, "") for a printable character, or (0, false, name) for a
// named key, or (0, false, "") for a key to ignore (modifiers, etc.).
func translateKey(vk uint32, shift, caps bool) (r rune, printable bool, name string) {
	switch {
	case vk >= 'A' && vk <= 'Z':
		upper := shift != caps // XOR: shift or caps (but not both) gives upper case
		if upper {
			return rune(vk), true, ""
		}
		return rune(vk - 'A' + 'a'), true, ""
	case vk >= '0' && vk <= '9':
		if shift {
			return digitShift[byte(vk)], true, ""
		}
		return rune(vk), true, ""
	}
	if r, ok := oemKeys[vk]; ok {
		if shift {
			return r.shifted, true, ""
		}
		return r.base, true, ""
	}
	if vk == vkSpace {
		return ' ', true, ""
	}
	if name, ok := namedVKs[vk]; ok {
		return 0, false, name
	}
	return 0, false, ""
}

const vkSpace = 0x20

// digitShift is the US-layout shifted form of each digit row key.
var digitShift = map[byte]rune{
	'1': '!', '2': '@', '3': '#', '4': '$', '5': '%',
	'6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
}

// oemKeys maps the US-layout OEM punctuation virtual keys to their base and
// shifted characters.
var oemKeys = map[uint32]struct{ base, shifted rune }{
	0xBA: {';', ':'},  // VK_OEM_1
	0xBB: {'=', '+'},  // VK_OEM_PLUS
	0xBC: {',', '<'},  // VK_OEM_COMMA
	0xBD: {'-', '_'},  // VK_OEM_MINUS
	0xBE: {'.', '>'},  // VK_OEM_PERIOD
	0xBF: {'/', '?'},  // VK_OEM_2
	0xC0: {'`', '~'},  // VK_OEM_3
	0xDB: {'[', '{'},  // VK_OEM_4
	0xDC: {'\\', '|'}, // VK_OEM_5
	0xDD: {']', '}'},  // VK_OEM_6
	0xDE: {'\'', '"'}, // VK_OEM_7
}

// namedVKs maps non-text virtual keys to the key names the Shortcut tool and the
// journey emitter understand.
var namedVKs = map[uint32]string{
	0x0D: "Enter",
	0x09: "Tab",
	0x08: "Backspace",
	0x1B: "Escape",
	0x2E: "Delete",
	0x2D: "Insert",
	0x24: "Home",
	0x23: "End",
	0x21: "PageUp",
	0x22: "PageDown",
	0x25: "Left",
	0x26: "Up",
	0x27: "Right",
	0x28: "Down",
	0x70: "F1", 0x71: "F2", 0x72: "F3", 0x73: "F4",
	0x74: "F5", 0x75: "F6", 0x76: "F7", 0x77: "F8",
	0x79: "F10", 0x7A: "F11", 0x7B: "F12",
}
