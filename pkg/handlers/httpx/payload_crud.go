package httpx

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/defektive/xodbox/pkg/model"
)

// invalidatePayloadCache clears the in-memory SortedPayloads cache so the next
// request reloads from the DB. Must be called after any create/update/delete.
func invalidatePayloadCache() {
	payloads = []*Payload{}
}

// validatePayload checks a payload before it is persisted.
func validatePayload(p *Payload) error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("name is required")
	}
	if p.Pattern == "" {
		return errors.New("pattern is required")
	}
	if _, err := regexp.Compile(p.Pattern); err != nil {
		return fmt.Errorf("invalid pattern regexp: %w", err)
	}
	if sc := strings.TrimSpace(p.Data.StatusCode); sc != "" {
		if _, err := strconv.Atoi(sc); err != nil {
			return errors.New("status_code must be numeric")
		}
	}
	return nil
}

// ListPayloads returns all HTTPX payloads (fresh from the DB, ordered).
func ListPayloads() []*Payload {
	var out []*Payload
	model.DB().Where("type = ?", PayloadName).
		Order("sort_order, project_id, pattern asc").Find(&out)
	return out
}

// PayloadByID fetches one HTTPX payload.
func PayloadByID(id uint) (*Payload, error) {
	var p Payload
	if err := model.DB().Where("type = ?", PayloadName).First(&p, id).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

// CreatePayload validates and inserts a payload, then invalidates the cache.
func CreatePayload(p *Payload) error {
	p.Type = PayloadName
	if err := validatePayload(p); err != nil {
		return err
	}
	p.Project = model.DefaultProject()
	if err := model.DB().Create(p).Error; err != nil {
		return err
	}
	invalidatePayloadCache()
	return nil
}

// UpdatePayload validates and saves changes to an existing payload. Saving the
// struct (rather than a column map) preserves the JSON serializer on Data.
func UpdatePayload(id uint, in *Payload) (*Payload, error) {
	existing, err := PayloadByID(id)
	if err != nil {
		return nil, err
	}
	in.Type = PayloadName
	if err := validatePayload(in); err != nil {
		return nil, err
	}
	existing.Name = in.Name
	existing.Description = in.Description
	existing.Pattern = in.Pattern
	existing.IsFinal = in.IsFinal
	existing.SortOrder = in.SortOrder
	existing.InternalFunction = in.InternalFunction
	existing.Data = in.Data
	if err := model.DB().Save(existing).Error; err != nil {
		return nil, err
	}
	invalidatePayloadCache()
	return existing, nil
}

// DeletePayload soft-deletes a payload and invalidates the cache.
func DeletePayload(id uint) error {
	if err := model.DB().Where("type = ?", PayloadName).Delete(&Payload{}, id).Error; err != nil {
		return err
	}
	invalidatePayloadCache()
	return nil
}
