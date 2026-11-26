package nodes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"gorm.io/gorm"
)

func loadAutomation() (model.NodeAutomation, error) {
	var s model.NodeAutomation
	err := database.GetDB().First(&s, 1).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s, nil
	}
	return s, err
}
func ProvisionSettings() (map[string]interface{}, error) {
	s, err := loadAutomation()
	return map[string]interface{}{"domain_suffix": s.DomainSuffix, "zone_id": s.ZoneId, "email": s.Email, "token_configured": s.DNSToken != "", "protocols": []string{"vless", "tuic", "hysteria2"}}, err
}
func SaveProvisionSettings(data []byte) error {
	var r struct {
		DomainSuffix string `json:"domain_suffix"`
		ZoneId       string `json:"zone_id"`
		Email        string `json:"email"`
		Token        string `json:"token"`
	}
	if json.Unmarshal(data, &r) != nil {
		return errors.New("invalid_dns_profile")
	}
	r.DomainSuffix = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.DomainSuffix), "."))
	r.ZoneId = strings.TrimSpace(r.ZoneId)
	r.Email = strings.TrimSpace(r.Email)
	if !validPublishedAddress(r.DomainSuffix) || net.ParseIP(r.DomainSuffix) != nil || !strings.Contains(r.DomainSuffix, ".") || (r.ZoneId != "" && len(r.ZoneId) != 32) {
		return errors.New("invalid_dns_profile")
	}
	for _, c := range r.ZoneId {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return errors.New("invalid_dns_profile")
		}
	}
	if r.Email != "" {
		if _, err := mail.ParseAddress(r.Email); err != nil {
			return errors.New("invalid_dns_profile")
		}
	}
	s, err := loadAutomation()
	if err != nil {
		return err
	}
	s.Id, s.DomainSuffix, s.ZoneId, s.Email = 1, r.DomainSuffix, r.ZoneId, r.Email
	if r.Token != "" {
		s.DNSToken, err = sealSecret(r.Token)
		if err != nil {
			return err
		}
	}
	if s.DNSToken == "" {
		return errors.New("dns_token_required")
	}
	token, err := openSecret(s.DNSToken)
	if err != nil {
		return errors.New("state_key_unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := resolveAutomationZone(ctx, token, &s); err != nil {
		return err
	}
	var zone struct {
		Name string `json:"name"`
	}
	if err = cloudflare(ctx, token, "GET", cloudflareZonesPath+s.ZoneId, nil, &zone); err != nil {
		return err
	}
	if s.DomainSuffix != zone.Name && !strings.HasSuffix(s.DomainSuffix, "."+zone.Name) {
		return errors.New("invalid_dns_profile")
	}
	return database.GetDB().Save(&s).Error
}
func automaticDomain(id uint, suffix string) string { return fmt.Sprintf("n-%d.%s", id, suffix) }

type cloudRecord struct {
	Id      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Comment string `json:"comment"`
}

func cloudflare(ctx context.Context, token, method, path string, body, target interface{}) error {
	var data io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		data = bytes.NewReader(b)
	}
	request, err := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4"+path, data)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 25 * time.Second}).Do(request)
	if err != nil {
		return errors.New("dns_api_unreachable")
	}
	defer response.Body.Close()
	var result struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&result) != nil || !result.Success || response.StatusCode/100 != 2 {
		return errors.New("dns_api_rejected")
	}
	return json.Unmarshal(result.Result, target)
}
func ensureNodeDNS(ctx context.Context, i *model.NodeInstallation) error {
	settings, err := loadAutomation()
	if err != nil {
		return err
	}
	token, err := openSecret(settings.DNSToken)
	if err != nil {
		return errors.New("state_key_unavailable")
	}
	path := cloudflareZonesPath + settings.ZoneId + "/dns_records"
	var list []cloudRecord
	if err = cloudflare(ctx, token, "GET", path+"?name="+url.QueryEscape(i.Domain), nil, &list); err != nil {
		return err
	}
	owner := fmt.Sprintf("S-UI managed node %d", i.NodeId)
	kind := "A"
	if net.ParseIP(i.IP).To4() == nil {
		kind = "AAAA"
	}
	body := map[string]interface{}{"type": kind, "name": i.Domain, "content": i.IP, "ttl": 60, "proxied": false, "comment": owner}
	var chosen *cloudRecord
	for index := range list {
		record := list[index]
		if record.Type != "A" && record.Type != "AAAA" {
			return errors.New("dns_name_occupied")
		}
		if record.Comment != owner {
			return errors.New("dns_name_occupied")
		}
		if record.Type == kind {
			snapshot := record
			chosen = &snapshot
		} else {
			var discarded interface{}
			if err = cloudflare(ctx, token, "DELETE", path+"/"+record.Id, nil, &discarded); err != nil {
				return err
			}
		}
	}
	var record cloudRecord
	if chosen == nil {
		err = cloudflare(ctx, token, "POST", path, body, &record)
	} else {
		err = cloudflare(ctx, token, "PATCH", path+"/"+chosen.Id, body, &record)
	}
	if err == nil {
		i.DNSRecordId = record.Id
	}
	return err
}

func resolveAutomationZone(ctx context.Context, token string, s *model.NodeAutomation) error {
	if s.ZoneId == "" {
		labels := strings.Split(s.DomainSuffix, ".")
		for len(labels) >= 2 {
			var zones []struct {
				Id string `json:"id"`
			}
			if err := cloudflare(ctx, token, "GET", "/zones?name="+url.QueryEscape(strings.Join(labels, ".")), nil, &zones); err != nil {
				return err
			}
			if len(zones) == 1 {
				s.ZoneId = zones[0].Id
				break
			}
			labels = labels[1:]
		}
		if s.ZoneId == "" {
			return errors.New("dns_zone_not_found")
		}
	}
	return nil
}
