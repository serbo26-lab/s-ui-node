package nodes

import (
	"github.com/alireza0/s-ui/database/model"
	"gorm.io/gorm"
)

func accountingClients(tx *gorm.DB, node model.Node, includeRevoked bool) ([]model.Client, error) {
	query := tx.Model(&model.Client{})
	if node.AssignmentMode == model.NodeAssignmentWhole || node.AssignmentMode == model.NodeAssignmentActivating {
		assignments := tx.Model(&model.ClientNode{}).Select("client_id").Where(whereNodeID, node.Id)
		if !includeRevoked {
			assignments = assignments.Where("active = ?", true)
		}
		query = query.Where("clients.id IN (?)", assignments)
	} else {
		assignments := tx.Model(&model.ClientNodeInbound{}).Select("client_node_inbounds.client_id").Joins("JOIN node_inbounds AS ni ON ni.id = client_node_inbounds.node_inbound_id").Where("ni.node_id = ?", node.Id)
		query = query.Where("clients.id IN (?)", assignments)
	}
	var clients []model.Client
	err := query.Find(&clients).Error
	return clients, err
}
