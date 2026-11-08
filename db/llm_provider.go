package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// LLMProvider is one AI endpoint: format, base URL, key, proxy, rate limit,
// session header and retry. Every model under it reuses that connection.
type LLMProvider struct {
	ID               int64         `json:"id"`
	Name             string        `json:"name"`
	Format           string        `json:"format"`
	BaseURL          string        `json:"base_url,omitempty"`
	Proxy            string        `json:"proxy,omitempty"`
	APIKey           string        `json:"-"`
	APIKeyHint       string        `json:"api_key_hint,omitempty"`
	RatePerSecond    float64       `json:"rate_per_second"`
	RatePerMinute    float64       `json:"rate_per_minute"`
	SessionHeaderKey string        `json:"session_header_key"`
	Retry            RetryOverride `json:"retry"`
	Models           []*LLMProfile `json:"models,omitempty"`
}

// LLMModelSpec is one model hanging off a provider. Connection fields are not
// here — they live on the provider and are copied onto the profile row.
type LLMModelSpec struct {
	Name            string `json:"name"`
	Model           string `json:"model"`
	ContextWindowK  int    `json:"context_window_k"`
	ThinkingType    string `json:"thinking_type"`
	ReasoningEffort string `json:"reasoning_effort"`
	Priority        int    `json:"priority"`
	PoolExclude     bool   `json:"pool_exclude"`
	// Streaming nil means "leave it" on update and "default on" on insert.
	Streaming      *bool  `json:"streaming"`
	MaxTokens      int    `json:"max_tokens"`
	MaxTokensField string `json:"max_tokens_field"`
}

var (
	ErrLLMProviderNotFound     = errors.New("LLM provider not found")
	ErrLLMProviderNameRequired = errors.New("LLM provider name is required")
	ErrLLMProviderFormat       = errors.New("LLM provider format is invalid")
	ErrLLMModelNameTaken       = errors.New("LLM model name is already in use")
	ErrLLMModelExists          = errors.New("LLM model already exists on this provider")
	ErrLLMModelRequired        = errors.New("at least one model is required")
)

func validLLMFormat(format string) bool {
	switch format {
	case "openai", "anthropic", "openai-responses":
		return true
	default:
		return false
	}
}

func profileKeyHint(key, existing string) string {
	if len(key) >= 4 {
		return "…" + key[len(key)-4:]
	}
	return existing
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// ListProviders returns every provider with its models nested in id order.
// A provider with no models is included so a half-saved endpoint can still be edited.
func (d *DB) ListProviders() ([]*LLMProvider, error) {
	rows, err := d.Query(`SELECT id, name, format, COALESCE(base_url,''), COALESCE(proxy,''), COALESCE(api_key_hint,''),
rate_per_second, rate_per_minute, COALESCE(session_header_key,''),
COALESCE(retry_connect_attempts,0), COALESCE(retry_connect_interval_ms,0),
COALESCE(retry_empty_attempts,0), COALESCE(retry_empty_interval_ms,0),
COALESCE(retry_stream_attempts,0), COALESCE(retry_stream_interval_ms,0)
FROM llm_providers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*LLMProvider
	byID := map[int64]*LLMProvider{}
	for rows.Next() {
		var p LLMProvider
		if err := rows.Scan(&p.ID, &p.Name, &p.Format, &p.BaseURL, &p.Proxy, &p.APIKeyHint,
			&p.RatePerSecond, &p.RatePerMinute, &p.SessionHeaderKey,
			&p.Retry.Connect.Attempts, &p.Retry.Connect.IntervalMS,
			&p.Retry.Empty.Attempts, &p.Retry.Empty.IntervalMS,
			&p.Retry.Stream.Attempts, &p.Retry.Stream.IntervalMS); err != nil {
			return nil, err
		}
		p.Models = []*LLMProfile{}
		out = append(out, &p)
		byID[p.ID] = &p
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	profs, err := d.ListProfiles()
	if err != nil {
		return nil, err
	}
	for _, model := range profs {
		if owner := byID[model.ProviderID]; owner != nil {
			owner.Models = append(owner.Models, model)
		}
	}
	return out, nil
}

// ProviderByID loads one provider including its API key, or nil if it does not exist.
func (d *DB) ProviderByID(id int64) (*LLMProvider, error) {
	var p LLMProvider
	err := d.QueryRow(`SELECT id, name, format, COALESCE(base_url,''), COALESCE(proxy,''), COALESCE(api_key,''), COALESCE(api_key_hint,''),
rate_per_second, rate_per_minute, COALESCE(session_header_key,''),
COALESCE(retry_connect_attempts,0), COALESCE(retry_connect_interval_ms,0),
COALESCE(retry_empty_attempts,0), COALESCE(retry_empty_interval_ms,0),
COALESCE(retry_stream_attempts,0), COALESCE(retry_stream_interval_ms,0)
FROM llm_providers WHERE id=$1`, id).Scan(&p.ID, &p.Name, &p.Format, &p.BaseURL, &p.Proxy, &p.APIKey, &p.APIKeyHint,
		&p.RatePerSecond, &p.RatePerMinute, &p.SessionHeaderKey,
		&p.Retry.Connect.Attempts, &p.Retry.Connect.IntervalMS,
		&p.Retry.Empty.Attempts, &p.Retry.Empty.IntervalMS,
		&p.Retry.Stream.Attempts, &p.Retry.Stream.IntervalMS)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

// SaveProvider updates an existing provider's connection and copies it onto every
// model under it. The name changes; model rows do not. An empty API key keeps the stored one.
func (d *DB) SaveProvider(p *LLMProvider) (int64, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return 0, ErrLLMProviderNameRequired
	}
	if p.ID <= 0 {
		return 0, ErrLLMProviderNotFound
	}
	tx, err := d.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	id, err := writeProvider(tx, p, p.APIKey == "")
	if err != nil {
		return 0, err
	}
	if err := syncProviderConnection(tx, id); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// CreateProvider inserts a provider and its first models in one transaction.
// An empty model list is rejected so the settings page never keeps a provider
// that has nothing to run.
func (d *DB) CreateProvider(p *LLMProvider, models []LLMModelSpec) (int64, []int64, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return 0, nil, ErrLLMProviderNameRequired
	}
	tx, err := d.Begin()
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback()
	p.ID = 0
	id, err := writeProvider(tx, p, false)
	if err != nil {
		return 0, nil, err
	}
	ids, _, err := addProviderModels(tx, id, models)
	if err != nil {
		return 0, nil, err
	}
	if len(ids) == 0 {
		return 0, nil, ErrLLMModelRequired
	}
	if err := tx.Commit(); err != nil {
		return 0, nil, err
	}
	return id, ids, nil
}

// AddProviderModels attaches models to an existing provider. A model id that is
// already present is skipped rather than duplicated. Names that collide with
// another profile get a numeric suffix.
func (d *DB) AddProviderModels(providerID int64, models []LLMModelSpec) ([]int64, int, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM llm_providers WHERE id=$1)`, providerID).Scan(&exists); err != nil {
		return nil, 0, err
	}
	if !exists {
		return nil, 0, ErrLLMProviderNotFound
	}
	ids, skipped, err := addProviderModels(tx, providerID, models)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return ids, skipped, nil
}

// UpdateModel changes one model's own knobs (名称、模型 id、上下文、思考、轮询、输出上限).
// The provider connection is left alone.
func (d *DB) UpdateModel(id int64, m LLMModelSpec) error {
	m.Name = strings.TrimSpace(m.Name)
	m.Model = strings.TrimSpace(m.Model)
	if m.MaxTokens < 0 {
		m.MaxTokens = 0
	}
	if m.Name == "" || m.Model == "" {
		return ErrLLMModelRequired
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var providerID int64
	err = tx.QueryRow(`SELECT COALESCE(provider_id,0) FROM llm_profiles WHERE id=$1`, id).Scan(&providerID)
	if err == sql.ErrNoRows {
		return ErrLLMProfileNotFound
	}
	if err != nil {
		return err
	}
	var taken bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM llm_profiles WHERE name=$1 AND id<>$2)`, m.Name, id).Scan(&taken); err != nil {
		return err
	}
	if taken {
		return ErrLLMModelNameTaken
	}
	if providerID != 0 {
		var dup bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM llm_profiles WHERE provider_id=$1 AND model=$2 AND id<>$3)`, providerID, m.Model, id).Scan(&dup); err != nil {
			return err
		}
		if dup {
			return ErrLLMModelExists
		}
	}
	res, err := tx.Exec(`UPDATE llm_profiles SET
name=$1, model=$2, context_window_k=$3, reasoning_effort=$4, priority=$5, pool_exclude=$6,
thinking_type=$7, streaming=COALESCE($8, streaming), max_tokens=$9, max_tokens_field=$10
WHERE id=$11`,
		m.Name, m.Model, m.ContextWindowK, m.ReasoningEffort, m.Priority, m.PoolExclude,
		m.ThinkingType, m.Streaming, m.MaxTokens, m.MaxTokensField, id)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrLLMModelNameTaken
		}
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrLLMProfileNotFound
	}
	return tx.Commit()
}

// DeleteProvider removes every model under the provider, then the provider itself
// once the last model is gone. If one of the models is the active profile, nothing
// is deleted. The returned ids are the models that were removed, so the caller can
// drop their circuit-breaker state.
func (d *DB) DeleteProvider(ctx context.Context, id int64) ([]int64, error) {
	var exists bool
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM llm_providers WHERE id=$1)`, id).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrLLMProviderNotFound
	}
	var active bool
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM llm_profiles WHERE provider_id=$1 AND is_default)`, id).Scan(&active); err != nil {
		return nil, err
	}
	if active {
		return nil, ErrActiveLLMProfileDelete
	}
	rows, err := d.Query(`SELECT id FROM llm_profiles WHERE provider_id=$1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var modelID int64
		if err := rows.Scan(&modelID); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, modelID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		if _, err := d.Exec(`DELETE FROM llm_providers WHERE id=$1`, id); err != nil {
			return nil, err
		}
		return nil, nil
	}
	deleted := make([]int64, 0, len(ids))
	for _, modelID := range ids {
		if err := d.DeleteProfileContext(ctx, modelID); err != nil {
			return deleted, err
		}
		deleted = append(deleted, modelID)
	}
	// The last model delete removes the provider. A row left behind (no models, gc
	// missed) is dropped here so the settings page does not keep an empty card.
	if _, err := d.Exec(`DELETE FROM llm_providers WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM llm_profiles WHERE provider_id=$1)`, id); err != nil {
		return deleted, err
	}
	return deleted, nil
}

func (d *DB) saveProfile(p *LLMProfile) (int64, error) {
	tx, err := d.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	providerID := p.ProviderID
	if p.ID != 0 {
		var stored sql.NullInt64
		err := tx.QueryRow(`SELECT provider_id FROM llm_profiles WHERE id=$1`, p.ID).Scan(&stored)
		if err == sql.ErrNoRows {
			return 0, ErrLLMProfileNotFound
		}
		if err != nil {
			return 0, err
		}
		if stored.Valid {
			providerID = stored.Int64
		}
	}
	// 改一个已有模型不能把提供商改名：名字属于整组模型。密钥留空表示沿用，
	// 还没归组的旧行要把行上的密钥带进新建的提供商，否则同步会把密钥抄丢。
	providerName := p.Name
	if providerID != 0 {
		var existing string
		err := tx.QueryRow(`SELECT name FROM llm_providers WHERE id=$1`, providerID).Scan(&existing)
		if err == sql.ErrNoRows {
			providerID = 0
		} else if err != nil {
			return 0, err
		} else {
			providerName = existing
		}
	}
	if p.ID != 0 && providerID == 0 && p.APIKey == "" {
		var key, hint sql.NullString
		if err := tx.QueryRow(`SELECT api_key, api_key_hint FROM llm_profiles WHERE id=$1`, p.ID).Scan(&key, &hint); err != nil {
			return 0, err
		}
		p.APIKey = key.String
		if p.APIKeyHint == "" {
			p.APIKeyHint = hint.String
		}
	}
	prov := &LLMProvider{
		ID:               providerID,
		Name:             providerName,
		Format:           p.Format,
		BaseURL:          p.BaseURL,
		Proxy:            p.Proxy,
		APIKey:           p.APIKey,
		APIKeyHint:       p.APIKeyHint,
		RatePerSecond:    p.RatePerSecond,
		RatePerMinute:    p.RatePerMinute,
		SessionHeaderKey: p.SessionHeaderKey,
		Retry:            p.Retry,
	}
	providerID, err = writeProvider(tx, prov, p.APIKey == "" && providerID != 0)
	if err != nil {
		return 0, err
	}
	p.ProviderID = providerID

	hint := profileKeyHint(p.APIKey, p.APIKeyHint)
	r := p.Retry.Clamped()
	var id int64
	if p.ID == 0 {
		err = tx.QueryRow(`INSERT INTO llm_profiles(
name,format,base_url,proxy,model,api_key,api_key_hint,rate_per_second,rate_per_minute,context_window_k,reasoning_effort,priority,pool_exclude,thinking_type,streaming,max_tokens,max_tokens_field,session_header_key,
retry_connect_attempts,retry_connect_interval_ms,retry_empty_attempts,retry_empty_interval_ms,retry_stream_attempts,retry_stream_interval_ms,provider_id)
VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),$5,NULLIF($6,''),NULLIF($7,''),$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25) RETURNING id`,
			p.Name, p.Format, p.BaseURL, p.Proxy, p.Model, p.APIKey, hint, p.RatePerSecond, p.RatePerMinute, p.ContextWindowK, p.ReasoningEffort, p.Priority, p.PoolExclude, p.ThinkingType, p.Streaming, p.MaxTokens, p.MaxTokensField, p.SessionHeaderKey,
			r.Connect.Attempts, r.Connect.IntervalMS, r.Empty.Attempts, r.Empty.IntervalMS, r.Stream.Attempts, r.Stream.IntervalMS, providerID).Scan(&id)
	} else {
		var res sql.Result
		res, err = tx.Exec(`UPDATE llm_profiles SET
name=$1,format=$2,base_url=NULLIF($3,''),proxy=NULLIF($4,''),model=$5,
api_key=CASE WHEN $6 <> '' THEN NULLIF($6,'') ELSE api_key END,
api_key_hint=CASE WHEN $6 <> '' THEN NULLIF($7,'') ELSE api_key_hint END,
rate_per_second=$8,rate_per_minute=$9,context_window_k=$10,reasoning_effort=$11,priority=$12,pool_exclude=$13,thinking_type=$14,streaming=$15,max_tokens=$16,max_tokens_field=$17,session_header_key=$18,
retry_connect_attempts=$19,retry_connect_interval_ms=$20,retry_empty_attempts=$21,retry_empty_interval_ms=$22,retry_stream_attempts=$23,retry_stream_interval_ms=$24,provider_id=$25
WHERE id=$26`,
			p.Name, p.Format, p.BaseURL, p.Proxy, p.Model, p.APIKey, hint, p.RatePerSecond, p.RatePerMinute, p.ContextWindowK, p.ReasoningEffort, p.Priority, p.PoolExclude, p.ThinkingType, p.Streaming, p.MaxTokens, p.MaxTokensField, p.SessionHeaderKey,
			r.Connect.Attempts, r.Connect.IntervalMS, r.Empty.Attempts, r.Empty.IntervalMS, r.Stream.Attempts, r.Stream.IntervalMS, providerID, p.ID)
		if err == nil {
			if n, _ := res.RowsAffected(); n != 1 {
				err = ErrLLMProfileNotFound
			} else {
				id = p.ID
			}
		}
	}
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrLLMModelNameTaken
		}
		return 0, err
	}
	if err := syncProviderConnection(tx, providerID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// writeProvider inserts or updates the shared connection. keepKey leaves the stored
// API key in place (the settings form sends a blank key to mean "don't change it").
// On insert, Name is the provider's display name and is not rewritten later by a
// model save — renaming a model must not rename the provider it shares.
func writeProvider(tx *sql.Tx, p *LLMProvider, keepKey bool) (int64, error) {
	if !validLLMFormat(p.Format) {
		return 0, ErrLLMProviderFormat
	}
	r := p.Retry.Clamped()
	hint := profileKeyHint(p.APIKey, p.APIKeyHint)
	if p.ID == 0 {
		var id int64
		err := tx.QueryRow(`INSERT INTO llm_providers(
name,format,base_url,proxy,api_key,api_key_hint,rate_per_second,rate_per_minute,session_header_key,
retry_connect_attempts,retry_connect_interval_ms,retry_empty_attempts,retry_empty_interval_ms,retry_stream_attempts,retry_stream_interval_ms)
VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
			strings.TrimSpace(p.Name), p.Format, p.BaseURL, p.Proxy, p.APIKey, hint, p.RatePerSecond, p.RatePerMinute, p.SessionHeaderKey,
			r.Connect.Attempts, r.Connect.IntervalMS, r.Empty.Attempts, r.Empty.IntervalMS, r.Stream.Attempts, r.Stream.IntervalMS).Scan(&id)
		return id, err
	}
	var (
		res sql.Result
		err error
	)
	if keepKey {
		res, err = tx.Exec(`UPDATE llm_providers SET
name=$1,format=$2,base_url=NULLIF($3,''),proxy=NULLIF($4,''),rate_per_second=$5,rate_per_minute=$6,session_header_key=$7,
retry_connect_attempts=$8,retry_connect_interval_ms=$9,retry_empty_attempts=$10,retry_empty_interval_ms=$11,retry_stream_attempts=$12,retry_stream_interval_ms=$13
WHERE id=$14`,
			strings.TrimSpace(p.Name), p.Format, p.BaseURL, p.Proxy, p.RatePerSecond, p.RatePerMinute, p.SessionHeaderKey,
			r.Connect.Attempts, r.Connect.IntervalMS, r.Empty.Attempts, r.Empty.IntervalMS, r.Stream.Attempts, r.Stream.IntervalMS, p.ID)
	} else {
		res, err = tx.Exec(`UPDATE llm_providers SET
name=$1,format=$2,base_url=NULLIF($3,''),proxy=NULLIF($4,''),api_key=NULLIF($5,''),api_key_hint=NULLIF($6,''),rate_per_second=$7,rate_per_minute=$8,session_header_key=$9,
retry_connect_attempts=$10,retry_connect_interval_ms=$11,retry_empty_attempts=$12,retry_empty_interval_ms=$13,retry_stream_attempts=$14,retry_stream_interval_ms=$15
WHERE id=$16`,
			strings.TrimSpace(p.Name), p.Format, p.BaseURL, p.Proxy, p.APIKey, hint, p.RatePerSecond, p.RatePerMinute, p.SessionHeaderKey,
			r.Connect.Attempts, r.Connect.IntervalMS, r.Empty.Attempts, r.Empty.IntervalMS, r.Stream.Attempts, r.Stream.IntervalMS, p.ID)
	}
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, ErrLLMProviderNotFound
	}
	return p.ID, nil
}

// syncProviderConnection copies the provider onto every model row. Runtime reads
// one llm_profiles row and never joins at call time; this is what keeps that copy honest.
// Switching the format off openai also drops max_completion_tokens, which only that format sends.
func syncProviderConnection(tx *sql.Tx, providerID int64) error {
	_, err := tx.Exec(`UPDATE llm_profiles p SET
format = v.format,
base_url = v.base_url,
proxy = v.proxy,
api_key = v.api_key,
api_key_hint = v.api_key_hint,
rate_per_second = v.rate_per_second,
rate_per_minute = v.rate_per_minute,
session_header_key = v.session_header_key,
retry_connect_attempts = v.retry_connect_attempts,
retry_connect_interval_ms = v.retry_connect_interval_ms,
retry_empty_attempts = v.retry_empty_attempts,
retry_empty_interval_ms = v.retry_empty_interval_ms,
retry_stream_attempts = v.retry_stream_attempts,
retry_stream_interval_ms = v.retry_stream_interval_ms,
max_tokens_field = CASE WHEN v.format = 'openai' THEN p.max_tokens_field ELSE '' END
FROM llm_providers v
WHERE v.id = $1 AND p.provider_id = v.id`, providerID)
	return err
}

func addProviderModels(tx *sql.Tx, providerID int64, models []LLMModelSpec) ([]int64, int, error) {
	seen := map[string]bool{}
	var ids []int64
	skipped := 0
	for i := range models {
		m := models[i]
		m.Model = strings.TrimSpace(m.Model)
		m.Name = strings.TrimSpace(m.Name)
		if m.Model == "" {
			skipped++
			continue
		}
		if seen[m.Model] {
			skipped++
			continue
		}
		seen[m.Model] = true
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM llm_profiles WHERE provider_id=$1 AND model=$2)`, providerID, m.Model).Scan(&exists); err != nil {
			return nil, 0, err
		}
		if exists {
			skipped++
			continue
		}
		if m.Name == "" {
			m.Name = m.Model
		}
		name, err := allocateProfileName(tx, m.Name)
		if err != nil {
			return nil, 0, err
		}
		streaming := true
		if m.Streaming != nil {
			streaming = *m.Streaming
		}
		if m.MaxTokens < 0 {
			m.MaxTokens = 0
		}
		var id int64
		err = tx.QueryRow(`INSERT INTO llm_profiles(
name, format, base_url, proxy, model, api_key, api_key_hint,
rate_per_second, rate_per_minute, context_window_k, reasoning_effort,
priority, pool_exclude, thinking_type, streaming, max_tokens, max_tokens_field,
session_header_key,
retry_connect_attempts, retry_connect_interval_ms,
retry_empty_attempts, retry_empty_interval_ms,
retry_stream_attempts, retry_stream_interval_ms,
provider_id)
SELECT $1, v.format, v.base_url, v.proxy, $2, v.api_key, v.api_key_hint,
v.rate_per_second, v.rate_per_minute, $3, $4,
$5, $6, $7, $8, $9, $10,
v.session_header_key,
v.retry_connect_attempts, v.retry_connect_interval_ms,
v.retry_empty_attempts, v.retry_empty_interval_ms,
v.retry_stream_attempts, v.retry_stream_interval_ms,
v.id
FROM llm_providers v WHERE v.id=$11
RETURNING id`,
			name, m.Model, m.ContextWindowK, m.ReasoningEffort,
			m.Priority, m.PoolExclude, m.ThinkingType, streaming, m.MaxTokens, m.MaxTokensField,
			providerID).Scan(&id)
		if err == sql.ErrNoRows {
			return nil, 0, ErrLLMProviderNotFound
		}
		if err != nil {
			if isUniqueViolation(err) {
				return nil, 0, ErrLLMModelNameTaken
			}
			return nil, 0, err
		}
		ids = append(ids, id)
	}
	return ids, skipped, nil
}

func allocateProfileName(tx *sql.Tx, base string) (string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "model"
	}
	name := base
	for n := range 50 {
		if n > 0 {
			name = fmt.Sprintf("%s (%d)", base, n+1)
		}
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM llm_profiles WHERE name=$1)`, name).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return name, nil
		}
	}
	return "", fmt.Errorf("模型名称「%s」已被占用", base)
}
