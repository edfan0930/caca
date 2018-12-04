package rbac

import (
	"github.com/casbin/casbin"
	"github.com/casbin/casbin/persist"
	mongodbadapter "github.com/casbin/mongodb-adapter"
)

var url string

type (
	//conf && rule base
	config struct {
		CONF    string
		Adapter persist.Adapter
	}
)

// SetURL --
// mongodb://account:pass@localhost:27017/db
//default db name "casbin"
func SetURL(u string) {
	url = u
	return
}

// NewConfig --
// mongodb://account:pass@localhost:27017/db
// default db name "casbin"
func NewConfig(u string) *config {
	a := mongodbadapter.NewAdapter(u)
	return &config{
		CONF:    "./rbac_with_services_model.conf",
		Adapter: a,
	}
}

func (c *config) Enforce(rvals ...interface{}) (b bool, err error) {
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}

	err = e.LoadPolicy()
	if err != nil {
		return
	}

	b, err = e.EnforceSafe(rvals...)
	return
}

func (c *config) AddPolicy(rvals ...interface{}) (b bool, err error) {
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}

	err = e.LoadPolicy()
	if err != nil {
		return
	}

	b, err = e.AddPolicySafe(rvals...)
	return
}

func (c *config) RemovePolicy(rvals ...interface{}) (b bool, err error) {
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}

	err = e.LoadPolicy()
	if err != nil {
		return
	}

	b, err = e.RemovePolicySafe(rvals...)
	return
}
