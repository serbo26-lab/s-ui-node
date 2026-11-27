package panel

import (
	ipmodel "github.com/alireza0/s-ui/antiabuse/model"
	"github.com/alireza0/s-ui/database/model"

	"gorm.io/gorm"
)

func HydrateClientPolicies(db *gorm.DB, clients []model.Client) error {
	if len(clients) == 0 {
		return nil
	}
	ids := make([]uint, 0, len(clients))
	for _, client := range clients {
		ids = append(ids, client.Id)
	}
	var rows []ipmodel.ClientRule
	if err := db.Where("client_id IN ?", ids).Find(&rows).Error; err != nil {
		return err
	}
	byID := make(map[uint]ipmodel.ClientRule, len(rows))
	for _, row := range rows {
		byID[row.ClientID] = row
	}
	for index := range clients {
		client := &clients[index]
		client.IPControl = &ipmodel.ClientPolicy{}
		if row, ok := byID[client.Id]; ok && row.CreatedAt == client.CreatedAt {
			limit := row.Limit
			client.IPControl.Limit = &limit
		}
	}
	return nil
}
