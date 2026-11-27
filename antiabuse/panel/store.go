package panel

import (
	"errors"
	"math"
	"slices"
	"time"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipmodel "github.com/alireza0/s-ui/antiabuse/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrConflict = errors.New("ip_control_conflict")
var ErrInvalid = errors.New("ip_control_invalid")

type Configuration struct {
	Revision          uint64              `json:"revision"`
	Enabled           bool                `json:"enabled"`
	ActivitySeconds   uint32              `json:"activity_seconds"`
	TransitionSeconds uint32              `json:"transition_seconds"`
	Groups            []ipmodel.GroupRule `json:"groups"`
}

func (c Configuration) Profile() engine.Profile {
	p := engine.DefaultProfile()
	p.Activity = time.Duration(c.ActivitySeconds) * time.Second
	p.Transition = time.Duration(c.TransitionSeconds) * time.Second
	return p
}

func (c Configuration) Validate() error {
	if c.Revision == 0 || c.Revision >= math.MaxInt64 || c.Groups == nil || c.Profile().Validate() != nil {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, group := range c.Groups {
		if group.Group == "" || seen[group.Group] {
			return ErrInvalid
		}
		seen[group.Group] = true
	}
	return nil
}

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) *Store { return &Store{db: db} }

// Initialize runs after the panel's ordinary schema migration, including after
// restore. It does not create an alternative database or a backup format.
func (s *Store) Initialize() error {
	defaults := engine.DefaultProfile()
	row := ipmodel.Settings{ID: 1, Revision: 1, ActivitySeconds: uint32(defaults.Activity / time.Second),
		TransitionSeconds: uint32(defaults.Transition / time.Second)}
	return s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error
}

func (s *Store) Configuration() (Configuration, error) {
	var row ipmodel.Settings
	groups := []ipmodel.GroupRule{}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&row, 1).Error; err != nil {
			return err
		}
		return tx.Order("`group`").Find(&groups).Error
	})
	if err != nil {
		return Configuration{}, err
	}
	return Configuration{Revision: row.Revision, Enabled: row.Enabled, ActivitySeconds: row.ActivitySeconds,
		TransitionSeconds: row.TransitionSeconds, Groups: groups}, nil
}

func (s *Store) SaveConfiguration(value Configuration) (Configuration, error) {
	if err := value.Validate(); err != nil {
		return Configuration{}, err
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		changed := tx.Model(&ipmodel.Settings{}).Where("id = 1 AND revision = ?", value.Revision).
			Updates(map[string]any{"revision": value.Revision + 1, "enabled": value.Enabled,
				"activity_seconds": value.ActivitySeconds, "transition_seconds": value.TransitionSeconds})
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected != 1 {
			return ErrConflict
		}
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&ipmodel.GroupRule{}).Error; err != nil {
			return err
		}
		if len(value.Groups) > 0 {
			if err := tx.Create(&value.Groups).Error; err != nil {
				return err
			}
		}
		return tx.Create(&ipmodel.Event{At: time.Now().Unix(), Code: "configuration_changed"}).Error
	})
	if err != nil {
		return Configuration{}, err
	}
	value.Revision++
	return value, nil
}

// SaveClientPolicy participates in the caller's client transaction. It never
// publishes a runtime decision before the enclosing transaction has committed.
func SaveClientPolicy(tx *gorm.DB, id uint, createdAt int64, value *ipmodel.ClientPolicy) error {
	if value == nil {
		return nil
	}
	if id == 0 {
		return ErrInvalid
	}
	if value.Limit == nil {
		return tx.Where("client_id = ?", id).Delete(&ipmodel.ClientRule{}).Error
	}
	row := ipmodel.ClientRule{ClientID: id, CreatedAt: createdAt, Limit: *value.Limit}
	return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "client_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"created_at", "limit"})}).Create(&row).Error
}

func DeleteClientPolicies(tx *gorm.DB, ids []uint) error {
	if len(ids) == 0 {
		return nil
	}
	return tx.Where("client_id IN ?", ids).Delete(&ipmodel.ClientRule{}).Error
}

func (s *Store) GroupNames() ([]string, error) {
	var clients []string
	if err := s.db.Table("clients").Distinct("group").Where("`group` <> ''").Pluck("group", &clients).Error; err != nil {
		return nil, err
	}
	var saved []string
	if err := s.db.Model(&ipmodel.GroupRule{}).Pluck("group", &saved).Error; err != nil {
		return nil, err
	}
	return uniqueGroups(clients, saved), nil
}

func uniqueGroups(groups ...[]string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, source := range groups {
		for _, name := range source {
			if !seen[name] {
				seen[name] = true
				result = append(result, name)
			}
		}
	}
	slices.Sort(result)
	return result
}

func (s *Store) Events(before uint64, limit int) ([]ipmodel.Event, error) {
	query := s.db.Order("id DESC").Limit(min(max(limit, 1), 200))
	if before > 0 {
		query = query.Where("id < ?", before)
	}
	rows := []ipmodel.Event{}
	err := query.Find(&rows).Error
	return rows, err
}

func (s *Store) PruneEvents(now time.Time) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("at < ?", now.Add(-7*24*time.Hour).Unix()).Delete(&ipmodel.Event{}).Error; err != nil {
			return err
		}
		return tx.Exec("DELETE FROM ip_control_events WHERE id NOT IN (SELECT id FROM ip_control_events ORDER BY id DESC LIMIT 10000)").Error
	})
}
