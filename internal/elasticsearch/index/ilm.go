package index

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/elastic/terraform-provider-elasticstack/internal/clients"
	"github.com/elastic/terraform-provider-elasticstack/internal/models"
	"github.com/elastic/terraform-provider-elasticstack/internal/utils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func ResourceIlm() *schema.Resource {
	ilmSchema := map[string]*schema.Schema{
		"name": {
			Description: "Identifier for the policy.",
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
		},
		"metadata": {
			Description:      "Optional user metadata about the ilm policy.",
			Type:             schema.TypeString,
			Optional:         true,
			ValidateFunc:     validation.StringIsJSON,
			DiffSuppressFunc: utils.DiffJsonSuppress,
		},
		"hot": {
			Description:  "The index is actively being updated and queried.",
			Type:         schema.TypeList,
			Optional:     true,
			MaxItems:     1,
			AtLeastOneOf: []string{"hot", "warm", "cold", "frozen", "delete"},
			Elem: &schema.Resource{
				Schema: getSchema("set_priority", "unfollow", "rollover", "readonly", "shrink", "forcemerge", "searchable_snapshot"),
			},
		},
		"warm": {
			Description:  "The index is no longer being updated but is still being queried.",
			Type:         schema.TypeList,
			Optional:     true,
			MaxItems:     1,
			AtLeastOneOf: []string{"hot", "warm", "cold", "frozen", "delete"},
			Elem: &schema.Resource{
				Schema: getSchema("set_priority", "unfollow", "readonly", "allocate", "migrate", "shrink", "forcemerge"),
			},
		},
		"cold": {
			Description:  "The index is no longer being updated and is queried infrequently. The information still needs to be searchable, but it’s okay if those queries are slower.",
			Type:         schema.TypeList,
			Optional:     true,
			MaxItems:     1,
			AtLeastOneOf: []string{"hot", "warm", "cold", "frozen", "delete"},
			Elem: &schema.Resource{
				Schema: getSchema("set_priority", "unfollow", "readonly", "searchable_snapshot", "allocate", "migrate", "freeze"),
			},
		},
		"frozen": {
			Description:  "The index is no longer being updated and is queried rarely. The information still needs to be searchable, but it’s okay if those queries are extremely slow.",
			Type:         schema.TypeList,
			Optional:     true,
			MaxItems:     1,
			AtLeastOneOf: []string{"hot", "warm", "cold", "frozen", "delete"},
			Elem: &schema.Resource{
				Schema: getSchema("searchable_snapshot"),
			},
		},
		"delete": {
			Description:  "The index is no longer needed and can safely be removed.",
			Type:         schema.TypeList,
			Optional:     true,
			MaxItems:     1,
			AtLeastOneOf: []string{"hot", "warm", "cold", "frozen", "delete"},
			Elem: &schema.Resource{
				Schema: getSchema("wait_for_snapshot", "delete"),
			},
		},
		"modified_date": {
			Description: "The DateTime of the last modification.",
			Type:        schema.TypeString,
			Computed:    true,
		},
	}

	utils.AddConnectionSchema(ilmSchema)

	return &schema.Resource{
		Description: "Creates or updates lifecycle policy. See: https://www.elastic.co/guide/en/elasticsearch/reference/current/ilm-put-lifecycle.html and https://www.elastic.co/guide/en/elasticsearch/reference/current/ilm-index-lifecycle.html",

		CreateContext: resourceIlmPut,
		UpdateContext: resourceIlmPut,
		ReadContext:   resourceIlmRead,
		DeleteContext: resourceIlmDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: ilmSchema,
	}
}

var suportedActions = map[string]*schema.Schema{
	"allocate": {
		Description: "Updates the index settings to change which nodes are allowed to host the index shards and change the number of replicas.",
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"number_of_replicas": {
					Description: "Number of replicas to assign to the index.",
					Type:        schema.TypeInt,
					Optional:    true,
				},
				"include": {
					Description:      "Assigns an index to nodes that have at least one of the specified custom attributes.",
					Type:             schema.TypeString,
					Optional:         true,
					ValidateFunc:     validation.StringIsJSON,
					DiffSuppressFunc: utils.DiffJsonSuppress,
				},
				"exclude": {
					Description:      "Assigns an index to nodes that have none of the specified custom attributes.",
					Type:             schema.TypeString,
					Optional:         true,
					ValidateFunc:     validation.StringIsJSON,
					DiffSuppressFunc: utils.DiffJsonSuppress,
				},
				"require": {
					Description:      "Assigns an index to nodes that have all of the specified custom attributes.",
					Type:             schema.TypeString,
					Optional:         true,
					ValidateFunc:     validation.StringIsJSON,
					DiffSuppressFunc: utils.DiffJsonSuppress,
				},
			},
		},
	},
	"delete": {
		Description: "Permanently removes the index.",
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"delete_searchable_snapshot": {
					Description: "Deletes the searchable snapshot created in a previous phase.",
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     true,
				},
			},
		},
	},
	"forcemerge": {
		Description: "Force merges the index into the specified maximum number of segments. This action makes the index read-only.",
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"max_num_segments": {
					Description:  "Number of segments to merge to. To fully merge the index, set to 1.",
					Type:         schema.TypeInt,
					Required:     true,
					ValidateFunc: validation.IntAtLeast(1),
				},
				"index_codec": {
					Description: "Codec used to compress the document store.",
					Type:        schema.TypeString,
					Optional:    true,
				},
			},
		},
	},
	"freeze": {
		Description: "Freeze the index to minimize its memory footprint.",
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"enabled": {
					Description: "Controls whether ILM freezes the index.",
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     true,
				},
			},
		},
	},
	"migrate": {
		Description: `Moves the index to the data tier that corresponds to the current phase by updating the "index.routing.allocation.include._tier_preference" index setting.`,
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"enabled": {
					Description: "Controls whether ILM automatically migrates the index during this phase.",
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     true,
				},
			},
		},
	},
	"readonly": {
		Description: "Makes the index read-only.",
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"enabled": {
					Description: "Controls whether ILM makes the index read-only.",
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     true,
				},
			},
		},
	},
	"rollover": {
		Description: "Rolls over a target to a new index when the existing index meets one or more of the rollover conditions.",
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"max_age": {
					Description: "Triggers rollover after the maximum elapsed time from index creation is reached.",
					Type:        schema.TypeString,
					Optional:    true,
				},
				"max_docs": {
					Description: "Triggers rollover after the specified maximum number of documents is reached.",
					Type:        schema.TypeInt,
					Optional:    true,
				},
				"max_size": {
					Description: "Triggers rollover when the index reaches a certain size.",
					Type:        schema.TypeString,
					Optional:    true,
				},
				"max_primary_shard_size": {
					Description: "Triggers rollover when the largest primary shard in the index reaches a certain size.",
					Type:        schema.TypeString,
					Optional:    true,
				},
			},
		},
	},
	"searchable_snapshot": {
		Description: "Takes a snapshot of the managed index in the configured repository and mounts it as a searchable snapshot.",
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"snapshot_repository": {
					Description: "Repository used to store the snapshot.",
					Type:        schema.TypeString,
					Required:    true,
				},
				"force_merge_index": {
					Description: "Force merges the managed index to one segment.",
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     true,
				},
			},
		},
	},
	"set_priority": {
		Description: "Sets a source index to read-only and shrinks it into a new index with fewer primary shards.",
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"priority": {
					Description:  "The priority for the index. Must be 0 or greater.",
					Type:         schema.TypeInt,
					Required:     true,
					ValidateFunc: validation.IntAtLeast(0),
				},
			},
		},
	},
	"shrink": {
		Description: "Sets a source index to read-only and shrinks it into a new index with fewer primary shards.",
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"number_of_shards": {
					Description: "Number of shards to shrink to.",
					Type:        schema.TypeInt,
					Optional:    true,
				},
				"max_primary_shard_size": {
					Description: "The max primary shard size for the target index.",
					Type:        schema.TypeString,
					Optional:    true,
				},
			},
		},
	},
	"unfollow": {
		Description: "Convert a follower index to a regular index. Performed automatically before a rollover, shrink, or searchable snapshot action.",
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"enabled": {
					Description: "Controls whether ILM makes the follower index a regular one.",
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     true,
				},
			},
		},
	},
	"wait_for_snapshot": {
		Description: "Waits for the specified SLM policy to be executed before removing the index. This ensures that a snapshot of the deleted index is available.",
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"policy": {
					Description: "Name of the SLM policy that the delete action should wait for.",
					Type:        schema.TypeString,
					Required:    true,
				},
			},
		},
	},
}

func getSchema(actions ...string) map[string]*schema.Schema {
	sch := make(map[string]*schema.Schema)
	for _, a := range actions {
		if action, ok := suportedActions[a]; ok {
			sch[a] = action
		}
	}
	// min age can be set for all the phases
	sch["min_age"] = &schema.Schema{
		Description: "ILM moves indices through the lifecycle according to their age. To control the timing of these transitions, you set a minimum age for each phase.",
		Type:        schema.TypeString,
		Optional:    true,
		Computed:    true,
	}
	return sch
}

func resourceIlmPut(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client, err := clients.NewApiClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	ilmId := d.Get("name").(string)
	id, diags := client.ID(ilmId)
	if diags.HasError() {
		return diags
	}

	policy, diags := expandIlmPolicy(d)
	if diags.HasError() {
		return diags
	}

	policyBytes, err := json.Marshal(map[string]interface{}{"policy": policy})
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[TRACE] sending new ILM policy to ES API: %s", policyBytes)

	req := client.ILM.PutLifecycle.WithBody(bytes.NewReader(policyBytes))
	res, err := client.ILM.PutLifecycle(ilmId, req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer res.Body.Close()
	if diags := utils.CheckError(res, "Unable to create or update the ILM policy"); diags.HasError() {
		return diags
	}

	d.SetId(id.String())
	return resourceIlmRead(ctx, d, meta)
}

func expandIlmPolicy(d *schema.ResourceData) (*models.Policy, diag.Diagnostics) {
	var diags diag.Diagnostics
	var policy models.Policy
	phases := make(map[string]models.Phase)

	policy.Name = d.Get("name").(string)

	if v, ok := d.GetOk("metadata"); ok {
		metadata := make(map[string]interface{})
		if err := json.NewDecoder(strings.NewReader(v.(string))).Decode(&metadata); err != nil {
			return nil, diag.FromErr(err)
		}
		policy.Metadata = metadata
	}

	if v, ok := d.GetOk("hot"); ok {
		// if defined it must contain only 1 entry map
		phase, diags := expandPhase(v.([]interface{})[0].(map[string]interface{}))
		if diags.HasError() {
			return nil, diags
		}
		phases["hot"] = *phase
	}
	if v, ok := d.GetOk("warm"); ok {
		// if defined it must contain only 1 entry map
		phase, diags := expandPhase(v.([]interface{})[0].(map[string]interface{}))
		if diags.HasError() {
			return nil, diags
		}
		phases["warm"] = *phase
	}
	if v, ok := d.GetOk("cold"); ok {
		// if defined it must contain only 1 entry map
		phase, diags := expandPhase(v.([]interface{})[0].(map[string]interface{}))
		if diags.HasError() {
			return nil, diags
		}
		phases["cold"] = *phase
	}
	if v, ok := d.GetOk("frozen"); ok {
		// if defined it must contain only 1 entry map
		phase, diags := expandPhase(v.([]interface{})[0].(map[string]interface{}))
		if diags.HasError() {
			return nil, diags
		}
		phases["frozen"] = *phase
	}
	if v, ok := d.GetOk("delete"); ok {
		// if defined it must contain only 1 entry map
		phase, diags := expandPhase(v.([]interface{})[0].(map[string]interface{}))
		if diags.HasError() {
			return nil, diags
		}
		phases["delete"] = *phase
	}

	policy.Phases = phases
	return &policy, diags
}

func expandPhase(p map[string]interface{}) (*models.Phase, diag.Diagnostics) {
	var diags diag.Diagnostics
	var phase models.Phase

	if v := p["min_age"].(string); v != "" {
		phase.MinAge = v
	}
	delete(p, "min_age")

	actions := make(map[string]models.Action)
	for actionName, action := range p {
		if a := action.([]interface{}); len(a) > 0 {
			switch actionName {
			case "allocate":
				actions[actionName] = expandAction(a, "number_of_replicas", "include", "exclude", "require")
			case "delete":
				actions[actionName] = expandAction(a, "delete_searchable_snapshot")
			case "forcemerge":
				actions[actionName] = expandAction(a, "max_num_segments", "index_codec")
			case "freeze":
				if a[0] != nil {
					ac := a[0].(map[string]interface{})
					if ac["enabled"].(bool) {
						actions[actionName] = expandAction(a)
					}
				}
			case "migrate":
				actions[actionName] = expandAction(a, "enabled")
			case "readonly":
				if a[0] != nil {
					ac := a[0].(map[string]interface{})
					if ac["enabled"].(bool) {
						actions[actionName] = expandAction(a)
					}
				}
			case "rollover":
				actions[actionName] = expandAction(a, "max_age", "max_docs", "max_size", "max_primary_shard_size")
			case "searchable_snapshot":
				actions[actionName] = expandAction(a, "snapshot_repository", "force_merge_index")
			case "set_priority":
				actions[actionName] = expandAction(a, "priority")
			case "shrink":
				actions[actionName] = expandAction(a, "number_of_shards", "max_primary_shard_size")
			case "unfollow":
				if a[0] != nil {
					ac := a[0].(map[string]interface{})
					if ac["enabled"].(bool) {
						actions[actionName] = expandAction(a)
					}
				}
			case "wait_for_snapshot":
				actions[actionName] = expandAction(a, "policy")
			default:
				diags = append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Unknown action defined.",
					Detail:   fmt.Sprintf(`Configured action "%s" is not supported`, actionName),
				})
				return nil, diags
			}
		}
	}

	phase.Actions = actions
	return &phase, diags
}

func expandAction(a []interface{}, settings ...string) map[string]interface{} {
	def := make(map[string]interface{})
	if action := a[0]; action != nil {
		for _, setting := range settings {
			if v, ok := action.(map[string]interface{})[setting]; ok && v != nil {
				switch t := v.(type) {
				case int:
					if t != 0 {
						def[setting] = t
					}
				case string:
					if t != "" {
						def[setting] = t
					}
				case bool:
					def[setting] = t
				default:
					// skip the rest
				}
			}
		}
	}
	return def
}

func resourceIlmRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client, err := clients.NewApiClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	id := d.Id()
	compId, diags := clients.CompositeIdFromStr(id)
	if diags.HasError() {
		return diags
	}
	policyId := compId.ResourceId

	req := client.ILM.GetLifecycle.WithPolicy(policyId)
	res, err := client.ILM.GetLifecycle(req)
	if err != nil {
		diag.FromErr(err)
	}
	if diags := utils.CheckError(res, "Unable to fetch ILM policy from the cluster."); diags.HasError() {
		return diags
	}
	defer res.Body.Close()

	// our API response
	ilm := map[string]struct {
		Policy   models.Policy `json:"policy"`
		Modified string        `json:"modified_date"`
	}{}
	if err := json.NewDecoder(res.Body).Decode(&ilm); err != nil {
		return diag.FromErr(err)
	}
	ilmDef := ilm[policyId]

	if err := d.Set("modified_date", ilmDef.Modified); err != nil {
		return diag.FromErr(err)
	}
	if ilmDef.Policy.Metadata != nil {
		metadata, err := json.Marshal(ilmDef.Policy.Metadata)
		if err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("metadata", string(metadata)); err != nil {
			return diag.FromErr(err)
		}
	}
	if v, ok := ilmDef.Policy.Phases["hot"]; ok {
		phase := flattenPhase("hot", v, d)
		if err := d.Set("hot", phase); err != nil {
			return diag.FromErr(err)
		}
	}
	if v, ok := ilmDef.Policy.Phases["warm"]; ok {
		phase := flattenPhase("warm", v, d)
		if err := d.Set("warm", phase); err != nil {
			return diag.FromErr(err)
		}
	}
	if v, ok := ilmDef.Policy.Phases["cold"]; ok {
		phase := flattenPhase("cold", v, d)
		if err := d.Set("cold", phase); err != nil {
			return diag.FromErr(err)
		}
	}
	if v, ok := ilmDef.Policy.Phases["frozen"]; ok {
		phase := flattenPhase("frozen", v, d)
		if err := d.Set("frozen", phase); err != nil {
			return diag.FromErr(err)
		}
	}
	if v, ok := ilmDef.Policy.Phases["delete"]; ok {
		phase := flattenPhase("delete", v, d)
		if err := d.Set("delete", phase); err != nil {
			return diag.FromErr(err)
		}
	}

	return diags
}

func flattenPhase(phaseName string, p models.Phase, d *schema.ResourceData) interface{} {
	out := make([]interface{}, 1)
	phase := make(map[string]interface{})
	enabled := make(map[string]interface{})
	ns := make(map[string]interface{})

	_, new := d.GetChange(phaseName)
	if new != nil && len(new.([]interface{})) > 0 {
		ns = new.([]interface{})[0].(map[string]interface{})
	}

	existsAndNotEMpty := func(key string, m map[string]interface{}) bool {
		if v, ok := m[key]; ok && len(v.([]interface{})) > 0 {
			return true
		}
		return false
	}
	for _, aCase := range []string{"readonly", "freeze", "unfollow"} {
		if existsAndNotEMpty(aCase, ns) {
			enabled["enabled"] = false
			phase[aCase] = []interface{}{enabled}
		}
	}

	if p.MinAge != "" {
		phase["min_age"] = p.MinAge
	}
	for actionName, action := range p.Actions {
		switch actionName {
		case "readonly", "freeze", "unfollow":
			enabled["enabled"] = true
			phase[actionName] = []interface{}{enabled}
		default:
			phase[actionName] = []interface{}{action}
		}
	}
	out[0] = phase
	return out
}

func resourceIlmDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client, err := clients.NewApiClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	id := d.Id()
	compId, diags := clients.CompositeIdFromStr(id)
	if diags.HasError() {
		return diags
	}
	res, err := client.ILM.DeleteLifecycle(compId.ResourceId)
	if err != nil {
		return diag.FromErr(err)
	}
	defer res.Body.Close()
	if diags := utils.CheckError(res, "Unable to delete ILM policy."); diags.HasError() {
		return diags
	}

	d.SetId("")
	return diags
}