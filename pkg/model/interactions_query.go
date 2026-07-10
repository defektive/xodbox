package model

import "gorm.io/gorm"

// InteractionFilter narrows and paginates an interaction query for the admin
// UI. Zero-value fields are ignored; Limit <= 0 means no limit. RequestTarget
// backs the "all hits to a path" (webhook-style) view.
type InteractionFilter struct {
	Handler       string
	RemoteAddr    string
	RequestTarget string
	Limit         int
	Offset        int
}

func (f InteractionFilter) apply(q *gorm.DB) *gorm.DB {
	if f.Handler != "" {
		q = q.Where("handler = ?", f.Handler)
	}
	if f.RemoteAddr != "" {
		q = q.Where("remote_addr = ?", f.RemoteAddr)
	}
	if f.RequestTarget != "" {
		q = q.Where("request_target = ?", f.RequestTarget)
	}
	return q
}

// QueryInteractions returns interactions matching the filter, newest first.
func QueryInteractions(f InteractionFilter) []Interaction {
	var out []Interaction
	q := f.apply(DB().Model(&Interaction{})).Order("created_at desc")
	if f.Limit > 0 {
		q = q.Limit(f.Limit)
	}
	if f.Offset > 0 {
		q = q.Offset(f.Offset)
	}
	q.Find(&out)
	return out
}

// CountInteractions returns the total number of interactions matching the
// filter (ignoring limit/offset), for pagination.
func CountInteractions(f InteractionFilter) int64 {
	var n int64
	f.apply(DB().Model(&Interaction{})).Count(&n)
	return n
}

// InteractionByID fetches a single interaction.
func InteractionByID(id uint) (*Interaction, error) {
	var i Interaction
	if err := DB().First(&i, id).Error; err != nil {
		return nil, err
	}
	return &i, nil
}
