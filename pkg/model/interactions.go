package model

import (
	"errors"

	"github.com/defektive/xodbox/pkg/util"
	"gorm.io/gorm"
)

// ErrNoPurgeConstraint is returned when a purge is attempted with no filter
// constraint, which would match (and delete) every interaction.
var ErrNoPurgeConstraint = errors.New("refusing to purge with no filter (specify --remote, --target, or --handler)")

type Interaction struct {
	gorm.Model

	PayloadID uint    `json:"payload_id"`
	Payload   Payload `json:"-"`

	ProjectID uint    `json:"project_id"`
	Project   Project `json:"-"`

	RemoteAddr    string `json:"remote_addr" gorm:"index:idx_remote_client"`
	RemotePort    string `json:"remote_port"`
	Handler       string `json:"handler"`
	RequestType   string `json:"request_type"`
	RequestTarget string `json:"request_target"`
	Protocol      string `json:"protocol"`
	UserAgent     string `json:"user_agent" gorm:"index:idx_remote_client"`
	Headers       string `json:"headers"`

	Data []byte `json:"data"`
}

func SortedInteractions(limit int) []Interaction {
	var interactions = []Interaction{}
	DB().Order("created_at desc").Limit(limit).Find(&interactions)
	return interactions
}

type Result struct {
	RemoteAddr  string `json:"remote_addr"`
	Total       int64  `json:"total"`
	MinuteGroup int64  `json:"minute_group"`
}

func getBotQuery() *gorm.DB {
	return db.Model(&Interaction{}).
		Select("remote_addr, count(*) total, strftime('%Y-%m-%d %H:%M', created_at) AS minute_group").
		Group("minute_group").
		Having("count(*) > 30")
}

func Bots() []Result {

	var results []Result
	getBotQuery().
		Find(&results)

	return results
}

func IsBot(remoteAddr string) bool {

	var results []Result
	getBotQuery().
		Where("remote_addr = ?", remoteAddr).
		Find(&results)

	return len(results) > 0
}

// InteractionPurgeFilter selects interactions to delete. Fields are ANDed
// together; a zero-value filter matches everything, so callers must supply at
// least one constraint (enforced by Matches returning false for an empty
// filter) to avoid nuking the whole table by accident.
type InteractionPurgeFilter struct {
	// Remotes is a list of source IPs/CIDRs; an interaction whose RemoteAddr
	// falls in any of them matches. Empty means "any source".
	Remotes []string
	// Target is a case-sensitive substring matched against RequestTarget
	// (the HTTP path / DNS qname). Empty means "any target".
	Target string
	// Handler restricts to a single handler name (e.g. "httpx"). Empty means
	// "any handler".
	Handler string
}

// hasConstraint reports whether the filter narrows anything. A filter with no
// constraint would match every row, which we refuse to purge silently.
func (f InteractionPurgeFilter) hasConstraint() bool {
	return len(f.Remotes) > 0 || f.Target != "" || f.Handler != ""
}

// MatchingInteractions returns the interactions the filter selects, applying
// the SQL-expressible constraints (handler, target substring) in the query and
// the CIDR match in Go (SQLite can't do CIDR containment). Returns an error if
// the filter has no constraint, or if any Remotes entry is an invalid CIDR/IP.
func MatchingInteractions(f InteractionPurgeFilter) ([]Interaction, error) {
	if !f.hasConstraint() {
		return nil, ErrNoPurgeConstraint
	}

	nets, err := util.ParseCIDRs(joinNonEmpty(f.Remotes))
	if err != nil {
		return nil, err
	}

	q := DB().Model(&Interaction{})
	if f.Handler != "" {
		q = q.Where("handler = ?", f.Handler)
	}
	if f.Target != "" {
		q = q.Where("request_target LIKE ?", "%"+f.Target+"%")
	}

	var rows []Interaction
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}

	if len(nets) == 0 {
		return rows, nil
	}

	var matched []Interaction
	for _, r := range rows {
		if util.IPInAny(r.RemoteAddr, nets) {
			matched = append(matched, r)
		}
	}
	return matched, nil
}

// PurgeInteractions deletes the interactions the filter selects and returns the
// number removed. See MatchingInteractions for filter semantics and errors.
func PurgeInteractions(f InteractionPurgeFilter) (int64, error) {
	matched, err := MatchingInteractions(f)
	if err != nil {
		return 0, err
	}
	if len(matched) == 0 {
		return 0, nil
	}

	ids := make([]uint, len(matched))
	for i, r := range matched {
		ids[i] = r.ID
	}
	tx := DB().Where("id IN ?", ids).Delete(&Interaction{})
	return tx.RowsAffected, tx.Error
}

// joinNonEmpty joins entries with commas so ParseCIDRs can split them back
// out; entries may themselves already be comma-separated.
func joinNonEmpty(parts []string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += ","
		}
		out += p
	}
	return out
}
