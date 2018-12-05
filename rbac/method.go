package rbac

import (
	"errors"

	"github.com/casbin/casbin"
	"github.com/casbin/casbin/persist"
	mongodbadapter "github.com/casbin/mongodb-adapter"
	"gopkg.in/mgo.v2/bson"
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

//check permission
func (c *config) Enforce(rvals ...interface{}) (b bool, err error) {
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}

	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}

	b, err = e.EnforceSafe(rvals...)
	return
}

//add policy
func (c *config) AddPolicy(rvals ...interface{}) (b bool, err error) {
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}

	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}

	b, err = e.AddPolicySafe(rvals...)
	if !b && err == nil {
		if g := e.HasPolicy(rvals...); g {
			err = errors.New("already exists")
		}
	}
	return
}

//remove policy
func (c *config) RemovePolicy(rvals ...interface{}) (b bool, err error) {
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}

	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}

	b, err = e.RemovePolicySafe(rvals...)
	return
}

//Add Group Policy
func (c *config) AddGroupPolicy(rvals ...interface{}) (b bool, err error) {
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}

	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}

	b = e.AddGroupingPolicy(rvals...)
	if !b {
		if g := e.HasGroupingPolicy(rvals...); g {
			err = errors.New("already exists")
		}
	}

	return
}

//Remove Group Plicy
//Not removed return false
func (c *config) RemoveGroupPolicy(rvals ...interface{}) (b bool, err error) {
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}

	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}

	b = e.RemoveGroupingPolicy(rvals...)

	return
}

//Policy exist return true
func (c *config) HasPolicy(rvals ...interface{}) (b bool, err error) {
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}

	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}

	b = e.HasPolicy(rvals...)

	return
}

//Group Policy exist return true
func (c *config) HasGroupPolicy(rvals ...interface{}) (b bool, err error) {
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}

	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}

	b = e.HasGroupingPolicy(rvals...)

	return
}
