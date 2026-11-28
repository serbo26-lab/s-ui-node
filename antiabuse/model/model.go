package model

import "net/netip"

type Settings struct {
	ID                uint           `gorm:"primaryKey;autoIncrement:false"`
	Revision          uint64         `gorm:"not null"`
	Enabled           bool           `gorm:"not null"`
	ActivitySeconds   uint32         `gorm:"not null"`
	TransitionSeconds uint32         `gorm:"not null"`
	TrustedProxies    []netip.Prefix `gorm:"serializer:json"`
}

func (Settings) TableName() string { return "ip_control_settings" }

type GroupRule struct {
	Group string `json:"group" gorm:"primaryKey"`
	Limit uint32 `json:"limit" gorm:"not null"`
}

func (GroupRule) TableName() string { return "ip_control_groups" }

type ClientRule struct {
	ClientID  uint  `gorm:"primaryKey;autoIncrement:false"`
	CreatedAt int64 `gorm:"not null;autoCreateTime:false"`
	Limit     uint32
}

func (ClientRule) TableName() string { return "ip_control_clients" }

// A missing extension preserves the previous override. A present extension
// with a null limit explicitly restores group inheritance.
type ClientPolicy struct {
	Limit *uint32 `json:"limit"`
}

type Event struct {
	ID        uint64 `json:"id" gorm:"primaryKey;autoIncrement"`
	At        int64  `json:"at" gorm:"index;not null"`
	ClientID  uint   `json:"client_id,omitempty" gorm:"index"`
	CreatedAt int64  `json:"client_created_at,omitempty" gorm:"autoCreateTime:false"`
	Code      string `json:"code" gorm:"not null"`
	Denied    uint32 `json:"denied"`
}

func (Event) TableName() string { return "ip_control_events" }
