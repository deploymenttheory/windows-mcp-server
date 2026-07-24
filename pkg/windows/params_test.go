package windows

import (
	"slices"
	"testing"
)

func TestOptionalBoolCoercion(t *testing.T) {
	cases := []struct {
		val  any
		want bool
	}{
		{true, true},
		{false, false},
		{"true", true},
		{"false", false},
		{"TRUE", true},
		{"1", true},
		{"0", false},
		{"yes", true},
		{"no", false},
		{nil, false}, // absent -> fallback
	}
	for _, c := range cases {
		args := map[string]any{}
		if c.val != nil {
			args["k"] = c.val
		}
		if got := OptionalBool(args, "k", false); got != c.want {
			t.Errorf("OptionalBool(%v) = %v, want %v", c.val, got, c.want)
		}
	}
}

func TestOptionalIntCoercion(t *testing.T) {
	cases := []struct {
		val     any
		want    int
		wantErr bool
	}{
		{float64(42), 42, false},
		{"7", 7, false},
		{" 9 ", 9, false},
		{"", 5, false}, // empty string -> fallback
		{"abc", 5, true},
	}
	for _, c := range cases {
		got, err := OptionalInt(map[string]any{"k": c.val}, "k", 5)
		if (err != nil) != c.wantErr {
			t.Errorf("OptionalInt(%v) err=%v, wantErr=%v", c.val, err, c.wantErr)
		}
		if err == nil && got != c.want {
			t.Errorf("OptionalInt(%v) = %d, want %d", c.val, got, c.want)
		}
	}
}

func TestOptionalIntSliceCoercion(t *testing.T) {
	// JSON array of numbers.
	got, err := OptionalIntSlice(map[string]any{"loc": []any{float64(10), float64(20)}}, "loc")
	if err != nil || !slices.Equal(got, []int{10, 20}) {
		t.Errorf("array form: got %v err %v", got, err)
	}
	// Stringified array (Claude Desktop anyOf stripping).
	got, err = OptionalIntSlice(map[string]any{"loc": "[30, 40]"}, "loc")
	if err != nil || !slices.Equal(got, []int{30, 40}) {
		t.Errorf("string form: got %v err %v", got, err)
	}
	// Absent.
	got, err = OptionalIntSlice(map[string]any{}, "loc")
	if err != nil || got != nil {
		t.Errorf("absent: got %v err %v", got, err)
	}
}

func TestRequiredString(t *testing.T) {
	if _, err := RequiredString(map[string]any{}, "k"); err == nil {
		t.Error("expected error for missing required string")
	}
	if _, err := RequiredString(map[string]any{"k": ""}, "k"); err == nil {
		t.Error("expected error for empty required string")
	}
	got, err := RequiredString(map[string]any{"k": "v"}, "k")
	if err != nil || got != "v" {
		t.Errorf("got %q err %v", got, err)
	}
}

func TestOptionalStringEnum(t *testing.T) {
	got, err := OptionalStringEnum(map[string]any{"m": "get"}, "m", "get", "get", "set")
	if err != nil || got != "get" {
		t.Errorf("valid enum: got %q err %v", got, err)
	}
	if _, err := OptionalStringEnum(map[string]any{"m": "bogus"}, "m", "get", "get", "set"); err == nil {
		t.Error("expected error for invalid enum value")
	}
}
