package option

import (
	"fmt"
	"slices"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

// H3CongestionControl selects the local HTTP/3 sender. The zero value retains
// the existing directional defaults; explicit JSON values must be nonempty.
type H3CongestionControl string

const (
	H3CongestionNewReno H3CongestionControl = "new_reno"
	H3CongestionCubic   H3CongestionControl = "cubic"
	H3CongestionBBR     H3CongestionControl = "bbr"
	H3CongestionNone    H3CongestionControl = "none"
)

func (c *H3CongestionControl) UnmarshalJSON(content []byte) error {
	var value string
	if err := json.Unmarshal(content, &value); err != nil {
		return fmt.Errorf("h3_congestion_control: %w", err)
	}
	if value == "" {
		return fmt.Errorf("h3_congestion_control must be a nonempty algorithm name")
	}
	parsed := H3CongestionControl(value)
	if err := parsed.Validate([]int{3}, true); err != nil {
		return err
	}
	*c = parsed
	return nil
}

func (c H3CongestionControl) Validate(versions []int, allowNone bool) error {
	if c == "" {
		return nil
	}
	switch c {
	case H3CongestionNewReno, H3CongestionCubic, H3CongestionBBR:
	case H3CongestionNone:
		if !allowNone {
			return fmt.Errorf("h3_congestion_control: none is only supported by MASQUE endpoints")
		}
	default:
		return fmt.Errorf("unknown h3_congestion_control: %q", c)
	}
	if !slices.Contains(versions, 3) {
		return fmt.Errorf("h3_congestion_control requires HTTP version 3")
	}
	return nil
}

// Add a conditional constraint without changing the schema of configurations
// which do not opt into congestion control selection.
func describeH3Congestion(node *schema.Node, server, defaultH3 bool) {
	version := &schema.Node{Enum: []any{3}}
	if server {
		version = schema.AnyOf(&schema.Node{Type: "integer", Const: 3}, &schema.Node{Type: "array", Contains: &schema.Node{Const: 3}})
		if defaultH3 {
			version.AnyOf = append(version.AnyOf, &schema.Node{Enum: []any{[]int{}}})
		}
	} else if defaultH3 {
		version.Enum = []any{0, 3}
	}
	properties := new(badjson.TypedMap[string, *schema.Node])
	properties.Put("version", version)
	constraint := &schema.Node{Properties: properties}
	if !defaultH3 {
		constraint.Required = []string{"version"}
	}
	node.AllOf = append(node.AllOf, &schema.Node{
		If: &schema.Node{Required: []string{"h3_congestion_control"}}, Then: constraint,
	})
}
