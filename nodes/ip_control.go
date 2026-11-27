package nodes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	ipcontrol "github.com/alireza0/s-ui/antiabuse/panel"
	"github.com/alireza0/s-ui/antiabuse/wire"
	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
)

type IPTransport struct{}

func (IPTransport) Open(ctx context.Context, node model.Node) (ipcontrol.Peer, error) {
	client, closeClient, err := controlClient(ctx, node)
	if err != nil {
		return nil, err
	}
	return &ipPeer{client: client, close: closeClient, node: node}, nil
}

type ipPeer struct {
	client *http.Client
	close  func()
	node   model.Node
}

func (p *ipPeer) Close() { p.close() }

func (p *ipPeer) Observe(ctx context.Context, config wire.Configuration) (wire.Header, []wire.Observation, time.Time, error) {
	requested := time.Now()
	page, err := p.readPage(ctx, config.Identity, "", 0, 0)
	if err != nil {
		return wire.Header{}, nil, requested, err
	}
	if page.Version != wire.Version || page.Identity != config.Identity {
		return wire.Header{}, nil, requested, wire.ErrInvalid
	}
	if page.Scope != config.Scope || page.ConfigRevision != config.Revision {
		config.Boot, config.Challenge = page.Boot, page.Challenge
		if err := config.Validate(); err != nil {
			return wire.Header{}, nil, requested, err
		}
		if err := p.put(ctx, wire.ConfigPath, config); err != nil {
			return wire.Header{}, nil, requested, err
		}
		requested = time.Now()
		page, err = p.readPage(ctx, config.Identity, "", 0, 0)
		if err != nil {
			return wire.Header{}, nil, requested, err
		}
	}
	assembly := wire.NewAssembly(config.Identity, config.Scope, config.Revision)
	for {
		if err := assembly.Add(page); err != nil {
			return wire.Header{}, nil, requested, err
		}
		if page.Next == nil {
			break
		}
		page, err = p.readPage(ctx, config.Identity, page.Boot, page.Sequence, *page.Next)
		if err != nil {
			return wire.Header{}, nil, requested, err
		}
	}
	header, entries, err := assembly.Result()
	return header, entries, requested, err
}

func (p *ipPeer) readPage(ctx context.Context, identity wire.Identity, boot string, sequence uint64, offset int) (wire.Page, error) {
	query := url.Values{"node_id": {strconv.FormatUint(identity.NodeID, 10)}, "epoch": {identity.Epoch},
		"access_revision": {strconv.FormatUint(identity.AccessRevision, 10)}}
	if sequence != 0 {
		query.Set("boot", boot)
		query.Set("sequence", strconv.FormatUint(sequence, 10))
		query.Set("offset", strconv.Itoa(offset))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.node.Address+wire.StatePath+"?"+query.Encode(), nil)
	if err != nil {
		return wire.Page{}, err
	}
	var page wire.Page
	err = p.request(request, &page)
	return page, err
}

func (p *ipPeer) Apply(ctx context.Context, value wire.Decision) error {
	if err := value.Validate(); err != nil {
		return err
	}
	var count int64
	err := database.GetDB().Model(&model.Node{}).Where("id = ? AND enable = ? AND address = ? AND management_generation = ? AND control_epoch = ?",
		p.node.Id, true, p.node.Address, p.node.ManagementGeneration, value.Identity.Epoch).Count(&count).Error
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("management_target_changed")
	}
	return p.put(ctx, wire.DecisionPath, value)
}

func (p *ipPeer) put(ctx context.Context, path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, p.node.Address+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	var response struct {
		Applied bool `json:"applied"`
	}
	if err := p.request(request, &response); err != nil {
		return err
	}
	if !response.Applied {
		return errors.New("ip_control_not_applied")
	}
	return nil
}

func (p *ipPeer) request(request *http.Request, value any) error {
	response, err := p.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("ip_control_unavailable")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 8<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return wire.ErrInvalid
	}
	return nil
}
