package rbac

import (
	"errors"

	"github.com/casbin/casbin"
	"github.com/casbin/casbin/persist"
	mongodbadapter "github.com/casbin/mongodb-adapter"
	"gopkg.in/mgo.v2/bson"
)

type (
	//conf && rule base
	config struct {
		CONF    string
		Adapter persist.Adapter
	}
)

// NewConfig --
// mongodb://account:pass@localhost:27017/db
// default db name "casbin"
func NewConfig(u string) *config {
	//預設conf ,rbac_with_services_model.conf, 可直接覆蓋更換
	//預設mongo adapter , 可直接覆蓋更換
	a := mongodbadapter.NewAdapter(u)
	return &config{
		CONF:    "./rbac_with_services_model.conf",
		Adapter: a,
	}
}

//check permission
//輸入參數依照conf設定
//這裡預設為 身份 , services name , api path , method
func (c *config) Enforce(rvals ...interface{}) (b bool, err error) {
	//instance cabin
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}
	//filter 身份
	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}
	//比對是否有相符資料存在
	b, err = e.EnforceSafe(rvals...)
	return
}

//add policy
//輸入參數依照conf設定
//這裡預設為 身份 , services name , api path , method
func (c *config) AddPolicy(rvals ...interface{}) (b bool, err error) {
	//instance cabin
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}
	//filter 身份
	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}
	//add policy
	b, err = e.AddPolicySafe(rvals...)
	//如果加入失敗和err nil時 , 檢查資料是否存在
	if !b && err == nil {
		if g := e.HasPolicy(rvals...); g {
			err = errors.New("already exists")
		}
	}
	return
}

//remove policy
//輸入參數依照conf設定
//這裡預設為 身份 , services name , api path , method
func (c *config) RemovePolicy(rvals ...interface{}) (b bool, err error) {
	//instance cabin
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}
	//filter 身份
	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}
	//remove policy
	b, err = e.RemovePolicySafe(rvals...)
	return
}

//Add Group Policy
func (c *config) AddGroupPolicy(rvals ...interface{}) (b bool, err error) {
	//instance casbin
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}
	//filter 身份
	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}
	//add user to group
	b = e.AddGroupingPolicy(rvals...)
	//添加失敗,檢查是否已存在
	if !b {
		if g := e.HasGroupingPolicy(rvals...); g {
			err = errors.New("already exists")
		}
	}

	return
}

//Remove Group Plicy , 將user 從group 移除
//Not removed return false
func (c *config) RemoveGroupPolicy(rvals ...interface{}) (b bool, err error) {
	//instance casbin
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}
	//filter 身份
	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}
	//remove group policy
	b = e.RemoveGroupingPolicy(rvals...)

	return
}

//Policy exist return true
func (c *config) HasPolicy(rvals ...interface{}) (b bool, err error) {
	//instance casbin
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}
	//filter 身份
	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}
	// 檢查是否已存在
	b = e.HasPolicy(rvals...)

	return
}

//Group Policy exist return true
func (c *config) HasGroupPolicy(rvals ...interface{}) (b bool, err error) {
	//instance casbin
	e, err := casbin.NewEnforcerSafe(c.CONF, c.Adapter)
	if err != nil {
		return
	}
	//filter 身份
	filter := &bson.M{"v0": rvals[0]}
	e.LoadFilteredPolicy(filter)
	if err != nil {
		return
	}
	//檢查user 是否存在該group
	b = e.HasGroupingPolicy(rvals...)

	return
}
