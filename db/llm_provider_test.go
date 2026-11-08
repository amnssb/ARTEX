package db

import (
	"context"
	"testing"
)

// TestProviderModelsShareConnection pins the reason the settings page groups
// models under a provider: one key and address, and a later edit of that
// connection shows up on every model. Model-only knobs (the output cap) stay put.
func TestProviderModelsShareConnection(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	// A crashed earlier run would leave the unique model names behind.
	_, _ = d.Exec(`DELETE FROM llm_profiles WHERE name LIKE 't-prov-share%' OR model LIKE 't-prov-model-%'`)
	_, _ = d.Exec(`DELETE FROM llm_providers WHERE name LIKE 't-prov-share%'`)

	id, modelIDs, err := d.CreateProvider(&LLMProvider{
		Name: "t-prov-share", Format: "openai", BaseURL: "https://t-prov-share.invalid/v1",
		APIKey: "secret-share-key", RatePerMinute: 12,
	}, []LLMModelSpec{
		{Name: "t-prov-share-a", Model: "t-prov-model-a", MaxTokens: 100, MaxTokensField: "max_completion_tokens"},
		{Model: "t-prov-model-b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM llm_profiles WHERE provider_id=$1 OR name LIKE 't-prov-share%' OR model LIKE 't-prov-model-%'`, id)
		_, _ = d.Exec(`DELETE FROM llm_providers WHERE id=$1 OR name LIKE 't-prov-share%'`, id)
	})
	if len(modelIDs) != 2 {
		t.Fatalf("model ids = %v, want 2", modelIDs)
	}

	a, err := d.ProfileByID(modelIDs[0])
	if err != nil || a == nil {
		t.Fatal(err)
	}
	b, err := d.ProfileByID(modelIDs[1])
	if err != nil || b == nil {
		t.Fatal(err)
	}
	if a.APIKey != "secret-share-key" || b.APIKey != "secret-share-key" {
		t.Fatalf("keys not shared: %q %q", a.APIKey, b.APIKey)
	}
	if a.BaseURL != "https://t-prov-share.invalid/v1" || b.BaseURL != a.BaseURL {
		t.Fatalf("base urls = %q %q", a.BaseURL, b.BaseURL)
	}
	if a.ProviderID != id || b.ProviderID != id {
		t.Fatalf("provider ids = %d %d, want %d", a.ProviderID, b.ProviderID, id)
	}
	if a.ProviderName != "t-prov-share" || b.ProviderName != "t-prov-share" {
		t.Fatalf("provider names = %q %q", a.ProviderName, b.ProviderName)
	}
	if b.Name != "t-prov-model-b" {
		t.Fatalf("unnamed model should take the model id as its name, got %q", b.Name)
	}
	if a.RatePerMinute != 12 || b.RatePerMinute != 12 {
		t.Fatalf("rates = %v %v", a.RatePerMinute, b.RatePerMinute)
	}
	if a.MaxTokens != 100 || a.MaxTokensField != "max_completion_tokens" {
		t.Fatalf("model cap = %d %q", a.MaxTokens, a.MaxTokensField)
	}

	if _, err := d.SaveProvider(&LLMProvider{
		ID: id, Name: "t-prov-share", Format: "openai",
		BaseURL: "https://t-prov-share.invalid/v1", APIKey: "secret-share-new", RatePerMinute: 12,
	}); err != nil {
		t.Fatal(err)
	}
	a, _ = d.ProfileByID(modelIDs[0])
	b, _ = d.ProfileByID(modelIDs[1])
	if a == nil || b == nil || a.APIKey != "secret-share-new" || b.APIKey != "secret-share-new" {
		t.Fatalf("key update did not reach both models: %+v %+v", a, b)
	}

	if err := d.UpdateModel(modelIDs[0], LLMModelSpec{
		Name: "t-prov-share-a", Model: "t-prov-model-a", MaxTokens: 50, MaxTokensField: "max_completion_tokens",
	}); err != nil {
		t.Fatal(err)
	}
	a, _ = d.ProfileByID(modelIDs[0])
	if a == nil || a.MaxTokens != 50 || a.APIKey != "secret-share-new" || a.ProviderName != "t-prov-share" {
		t.Fatalf("model update disturbed the shared connection: %+v", a)
	}

	// A blank key means "keep it"; the new address still applies to every model.
	if _, err := d.SaveProvider(&LLMProvider{
		ID: id, Name: "t-prov-share-renamed", Format: "openai",
		BaseURL: "https://t-prov-share.invalid/v2", RatePerMinute: 3,
	}); err != nil {
		t.Fatal(err)
	}
	a, _ = d.ProfileByID(modelIDs[0])
	b, _ = d.ProfileByID(modelIDs[1])
	if a == nil || b == nil || a.APIKey != "secret-share-new" || b.APIKey != a.APIKey {
		t.Fatalf("blank key update dropped the key: %+v %+v", a, b)
	}
	if a.BaseURL != "https://t-prov-share.invalid/v2" || b.BaseURL != a.BaseURL || a.RatePerMinute != 3 || b.RatePerMinute != 3 {
		t.Fatalf("connection did not fan out: %+v %+v", a, b)
	}
	if a.MaxTokens != 50 || a.ProviderName != "t-prov-share-renamed" || b.ProviderName != "t-prov-share-renamed" {
		t.Fatalf("rename/cap = %+v %+v", a, b)
	}

	added, skipped, err := d.AddProviderModels(id, []LLMModelSpec{
		{Model: "t-prov-model-a"},
		{Model: "t-prov-model-c"},
	})
	if err != nil || skipped != 1 || len(added) != 1 {
		t.Fatalf("add models ids=%v skipped=%d err=%v", added, skipped, err)
	}
	c, err := d.ProfileByID(added[0])
	if err != nil || c == nil || c.APIKey != "secret-share-new" || c.BaseURL != a.BaseURL {
		t.Fatalf("new model did not inherit the connection: %+v %v", c, err)
	}

	if err := d.DeleteProfile(modelIDs[1]); err != nil {
		t.Fatal(err)
	}
	if prov, err := d.ProviderByID(id); err != nil || prov == nil {
		t.Fatalf("provider gone while models remain: %+v %v", prov, err)
	}
	if _, err := d.DeleteProvider(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if prov, err := d.ProviderByID(id); err != nil || prov != nil {
		t.Fatalf("provider still present after delete: %+v %v", prov, err)
	}
}

// TestProviderBackfillGroupsIdenticalConnections checks the startup migration:
// two models with the same address, proxy and key become one provider, and the
// older row's rate wins. A different proxy stays its own provider.
func TestProviderBackfillGroupsIdenticalConnections(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM llm_profiles WHERE name LIKE 't-merge-%'`)
		_, _ = d.Exec(`DELETE FROM llm_providers WHERE base_url LIKE 'https://t-merge.invalid%' OR name LIKE 't-merge%'`)
		d.Close()
	})
	_, _ = d.Exec(`DELETE FROM llm_profiles WHERE name LIKE 't-merge-%'`)
	_, _ = d.Exec(`DELETE FROM llm_providers WHERE base_url LIKE 'https://t-merge.invalid%' OR name LIKE 't-merge%'`)

	if _, err := d.Exec(`INSERT INTO llm_profiles(name, format, base_url, api_key, model, proxy, rate_per_minute, session_header_key) VALUES
		('t-merge-a','openai','https://t-merge.invalid/v1','merge-key','m-a','',7,'x-first'),
		('t-merge-b','openai','https://t-merge.invalid/v1','merge-key','m-b','',9,'x-second'),
		('t-merge-c','openai','https://t-merge.invalid/v1','merge-key','m-c','socks5://127.0.0.1:1080',1,'')`); err != nil {
		t.Fatal(err)
	}
	// Schema runs on Open. Re-opening is what a process restart does, and that is
	// when ungrouped rows get a provider.
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}

	type row struct {
		name       string
		providerID int64
		rate       float64
		header     string
		proxy      string
	}
	rows, err := d.Query(`SELECT name, provider_id, rate_per_minute, COALESCE(session_header_key,''), COALESCE(proxy,'')
FROM llm_profiles WHERE name LIKE 't-merge-%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.name, &r.providerID, &r.rate, &r.header, &r.proxy); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("rows = %+v, want 3", got)
	}
	if got[0].name != "t-merge-a" || got[1].name != "t-merge-b" || got[2].name != "t-merge-c" {
		t.Fatalf("names = %+v", got)
	}
	if got[0].providerID == 0 || got[0].providerID != got[1].providerID {
		t.Fatalf("same connection should share a provider: %+v", got)
	}
	if got[2].providerID == 0 || got[2].providerID == got[0].providerID {
		t.Fatalf("different proxy should stay its own provider: %+v", got)
	}
	if got[0].rate != 7 || got[1].rate != 7 || got[0].header != "x-first" || got[1].header != "x-first" {
		t.Fatalf("group should keep the oldest connection extras: %+v", got)
	}
	if got[2].rate != 1 || got[2].proxy != "socks5://127.0.0.1:1080" {
		t.Fatalf("solo proxy row was overwritten: %+v", got[2])
	}
	var key string
	if err := d.QueryRow(`SELECT COALESCE(api_key,'') FROM llm_providers WHERE id=$1`, got[0].providerID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	if key != "merge-key" {
		t.Fatalf("provider key = %q", key)
	}
}
