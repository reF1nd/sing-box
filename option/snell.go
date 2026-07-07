package option

import (
	"reflect"

	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

type _SnellInboundOptions struct {
	Version int `json:"version" enum:"5,6"`
	AbstractSnellInboundOptions
	ObfsOptions SnellObfsServerOptions `json:"-"`
	V6Options   SnellV6Options         `json:"-"`
}

type AbstractSnellInboundOptions struct {
	ListenOptions
	PSK                     string      `json:"psk,omitempty"`
	Users                   []SnellUser `json:"users,omitempty"`
	MultiUserAuthentication string      `json:"multi_user_authentication,omitempty" enum:"userkey,psk"`
}

type SnellInboundOptions _SnellInboundOptions

func (o *SnellInboundOptions) UnmarshalJSON(content []byte) error {
	err := json.Unmarshal(content, (*_SnellInboundOptions)(o))
	if err != nil {
		return err
	}
	var versionOptions any
	switch o.Version {
	case 5:
		versionOptions = &o.ObfsOptions
	case 6:
		versionOptions = &o.V6Options
	case 0:
		return E.New("snell: missing version")
	default:
		return E.New("snell: unsupported version: ", o.Version)
	}
	err = badjson.UnmarshallExcluded(content, (*_SnellInboundOptions)(o), versionOptions)
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(content, &fields); err != nil {
		return err
	}
	_, pskConfigured := fields["psk"]
	_, authenticationConfigured := fields["multi_user_authentication"]
	if len(o.Users) == 0 {
		if authenticationConfigured {
			return E.New("snell: multi_user_authentication requires users")
		}
		if !pskConfigured || o.PSK == "" {
			return E.New("snell: psk is required")
		}
		return nil
	}
	authentication := o.MultiUserAuthentication
	if authentication == "" {
		authentication = "userkey"
	}
	switch authentication {
	case "userkey":
		if !pskConfigured || o.PSK == "" {
			return E.New("snell: psk is required with userkey multi-user authentication")
		}
		for index, user := range o.Users {
			if user.pskConfigured {
				return E.New("snell: users[", index, "].psk is not allowed with userkey authentication")
			}
			if !user.userKeyConfigured || user.UserKey == "" {
				return E.New("snell: users[", index, "].userkey is required")
			}
		}
	case "psk":
		if pskConfigured {
			return E.New("snell: top-level psk is not allowed with psk multi-user authentication")
		}
		for index, user := range o.Users {
			if user.userKeyConfigured {
				return E.New("snell: users[", index, "].userkey is not allowed with psk authentication")
			}
			if !user.pskConfigured || user.PSK == "" {
				return E.New("snell: users[", index, "].psk is required")
			}
		}
	default:
		return E.New("snell: unknown multi_user_authentication: ", o.MultiUserAuthentication)
	}
	return nil
}

func (o SnellInboundOptions) MarshalJSON() ([]byte, error) {
	var versionOptions any
	switch o.Version {
	case 5:
		versionOptions = o.ObfsOptions
	case 6:
		versionOptions = o.V6Options
	case 0:
		return nil, E.New("snell: missing version")
	default:
		return nil, E.New("snell: unsupported version: ", o.Version)
	}
	return badjson.MarshallObjects(_SnellInboundOptions(o), versionOptions)
}

func (o SnellInboundOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return schema.DiscriminatedUnion(builder, "version", true, []schema.UnionVariant{
		{Value: 5, StructType: reflect.TypeFor[SnellObfsServerOptions]()},
		{Value: 6, StructType: reflect.TypeFor[SnellV6Options]()},
	}, func(variant *schema.Node) error {
		return builder.FlattenStruct(variant, reflect.TypeFor[AbstractSnellInboundOptions]())
	})
}

type _SnellOutboundOptions struct {
	Version int `json:"version" enum:"1,2,3,4,5,6"`
	AbstractSnellOutboundOptions
	ObfsOptions SnellObfsClientOptions `json:"-"`
	V6Options   SnellV6OutboundOptions `json:"-"`
}

type AbstractSnellOutboundOptions struct {
	DialerOptions
	ServerOptions
	PSK     string      `json:"psk"`
	UserKey string      `json:"userkey,omitempty"`
	Reuse   bool        `json:"reuse,omitempty"`
	Network NetworkList `json:"network,omitempty"`
}

type SnellOutboundOptions _SnellOutboundOptions

func (o *SnellOutboundOptions) UnmarshalJSON(content []byte) error {
	err := json.Unmarshal(content, (*_SnellOutboundOptions)(o))
	if err != nil {
		return err
	}
	var versionOptions any
	switch o.Version {
	case 1, 2, 3, 4, 5:
		versionOptions = &o.ObfsOptions
	case 6:
		versionOptions = &o.V6Options
	case 0:
		return E.New("snell: missing version")
	default:
		return E.New("snell: unsupported version: ", o.Version)
	}
	return badjson.UnmarshallExcluded(content, (*_SnellOutboundOptions)(o), versionOptions)
}

func (o SnellOutboundOptions) MarshalJSON() ([]byte, error) {
	var versionOptions any
	switch o.Version {
	case 1, 2, 3, 4, 5:
		versionOptions = o.ObfsOptions
	case 6:
		versionOptions = o.V6Options
	case 0:
		return nil, E.New("snell: missing version")
	default:
		return nil, E.New("snell: unsupported version: ", o.Version)
	}
	return badjson.MarshallObjects(_SnellOutboundOptions(o), versionOptions)
}

func (o SnellOutboundOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	buildBase := func(variant *schema.Node) error {
		return builder.FlattenStruct(variant, reflect.TypeFor[AbstractSnellOutboundOptions]())
	}
	union, err := schema.DiscriminatedUnion(builder, "version", true, []schema.UnionVariant{
		{Value: 1, StructType: reflect.TypeFor[SnellObfsClientOptions]()},
		{Value: 2, StructType: reflect.TypeFor[SnellObfsClientOptions]()},
		{Value: 3, StructType: reflect.TypeFor[SnellObfsClientOptions]()},
		{Value: 4, StructType: reflect.TypeFor[SnellObfsClientModernOptions]()},
		{Value: 5, StructType: reflect.TypeFor[SnellObfsClientModernOptions]()},
		{Value: 6, StructType: reflect.TypeFor[SnellV6OutboundOptions]()},
	}, buildBase)
	if err != nil {
		return nil, err
	}
	return union, nil
}

type SnellObfsServerOptions struct {
	ObfsMode string `json:"obfs_mode,omitempty" enum:"none,http"`
}

type SnellUser struct {
	Name    string `json:"name,omitempty"`
	UserKey string `json:"userkey,omitempty"`
	PSK     string `json:"psk,omitempty"`

	userKeyConfigured bool
	pskConfigured     bool
}

type snellUserSchema struct {
	Name    string `json:"name,omitempty"`
	UserKey string `json:"userkey,omitempty"`
	PSK     string `json:"psk,omitempty"`
}

func (u SnellUser) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("SnellUser", func() (*schema.Node, error) {
		node := schema.StrictObject()
		err := builder.FlattenStruct(node, reflect.TypeFor[snellUserSchema]())
		if err != nil {
			return nil, err
		}
		return node, nil
	})
}

func (u *SnellUser) UnmarshalJSON(content []byte) error {
	type rawSnellUser struct {
		Name    string  `json:"name,omitempty"`
		UserKey *string `json:"userkey"`
		PSK     *string `json:"psk"`
	}
	var raw rawSnellUser
	if err := json.Unmarshal(content, &raw); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		return err
	}
	u.Name = raw.Name
	_, u.userKeyConfigured = fields["userkey"]
	_, u.pskConfigured = fields["psk"]
	if raw.UserKey != nil {
		u.UserKey = *raw.UserKey
	}
	if raw.PSK != nil {
		u.PSK = *raw.PSK
	}
	return nil
}

type SnellObfsClientOptions struct {
	ObfsMode string `json:"obfs_mode,omitempty" enum:"none,http,tls"`
	ObfsHost string `json:"obfs_host,omitempty"`
}

type SnellObfsClientModernOptions struct {
	ObfsMode string `json:"obfs_mode,omitempty" enum:"none,http"`
	ObfsHost string `json:"obfs_host,omitempty"`
}

type SnellV6Options struct {
	Mode string `json:"mode,omitempty" enum:"default,unshaped,unsafe-raw"`
}

type SnellV6OutboundOptions struct {
	Mode          string `json:"mode,omitempty" enum:"default,unshaped,unsafe-raw"`
	QUICProxyMode bool   `json:"quic_proxy_mode,omitempty"`
}
