package option

import (
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

type _SnellInboundOptions struct {
	ListenOptions
	Version                 int                    `json:"version"`
	PSK                     string                 `json:"psk,omitempty"`
	Users                   []SnellUser            `json:"users,omitempty"`
	MultiUserAuthentication string                 `json:"multi_user_authentication,omitempty"`
	ObfsOptions             SnellObfsServerOptions `json:"-"`
	V6Options               SnellV6Options         `json:"-"`
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
	return badjson.MarshallObjects((_SnellInboundOptions)(o), versionOptions)
}

type _SnellOutboundOptions struct {
	DialerOptions
	ServerOptions
	Version     int                    `json:"version"`
	PSK         string                 `json:"psk"`
	UserKey     string                 `json:"userkey,omitempty"`
	Reuse       bool                   `json:"reuse,omitempty"`
	Network     NetworkList            `json:"network,omitempty"`
	ObfsOptions SnellObfsClientOptions `json:"-"`
	V6Options   SnellV6Options         `json:"-"`
}

type SnellOutboundOptions _SnellOutboundOptions

func (o *SnellOutboundOptions) UnmarshalJSON(content []byte) error {
	err := json.Unmarshal(content, (*_SnellOutboundOptions)(o))
	if err != nil {
		return err
	}
	var versionOptions any
	switch o.Version {
	case 0, 1, 2, 3, 4, 5:
		versionOptions = &o.ObfsOptions
	case 6:
		versionOptions = &o.V6Options
	default:
		return E.New("snell: unsupported version: ", o.Version)
	}
	return badjson.UnmarshallExcluded(content, (*_SnellOutboundOptions)(o), versionOptions)
}

func (o SnellOutboundOptions) MarshalJSON() ([]byte, error) {
	var versionOptions any
	switch o.Version {
	case 0, 1, 2, 3, 4, 5:
		versionOptions = o.ObfsOptions
	case 6:
		versionOptions = o.V6Options
	default:
		return nil, E.New("snell: unsupported version: ", o.Version)
	}
	return badjson.MarshallObjects((_SnellOutboundOptions)(o), versionOptions)
}

type SnellObfsServerOptions struct {
	ObfsMode string `json:"obfs_mode,omitempty"`
}

type SnellUser struct {
	Name    string `json:"name,omitempty"`
	UserKey string `json:"userkey,omitempty"`
	PSK     string `json:"psk,omitempty"`

	userKeyConfigured bool
	pskConfigured     bool
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
	ObfsMode string `json:"obfs_mode,omitempty"`
	ObfsHost string `json:"obfs_host,omitempty"`
}

type SnellV6Options struct {
	Mode string `json:"mode,omitempty"`
}
