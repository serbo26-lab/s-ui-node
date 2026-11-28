package database

import ipmodel "github.com/alireza0/s-ui/antiabuse/model"

func ipControlSchema() []table {
	return []table{
		{"ip_control_settings", &ipmodel.Settings{}, copyRows[ipmodel.Settings]},
		{"ip_control_groups", &ipmodel.GroupRule{}, copyRows[ipmodel.GroupRule]},
		{"ip_control_clients", &ipmodel.ClientRule{}, copyRows[ipmodel.ClientRule]},
		{"ip_control_events", &ipmodel.Event{}, copyRows[ipmodel.Event]},
	}
}
