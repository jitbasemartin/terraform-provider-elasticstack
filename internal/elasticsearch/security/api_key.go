package security

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/elastic/terraform-provider-elasticstack/internal/clients"
	"github.com/elastic/terraform-provider-elasticstack/internal/models"
	"github.com/elastic/terraform-provider-elasticstack/internal/utils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func ResourceApiKey() *schema.Resource {
	apikeySchema := map[string]*schema.Schema{
		"id": {
			Description: "Internal identifier of the resource",
			Type:        schema.TypeString,
			Computed:    true,
		},
		"name": {
			Description: "Specifies the name for this API key.",
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			ValidateFunc: validation.All(
				validation.StringLenBetween(1, 1024),
				validation.StringMatch(regexp.MustCompile(`^[[:graph:]]+$`), "must contain alphanumeric characters (a-z, A-Z, 0-9), spaces, punctuation, and printable symbols in the Basic Latin (ASCII) block. Leading or trailing whitespace is not allowed"),
			),
		},
		"role_descriptors": {
			Description: "An array of role descriptors for this API key.",
			Type:        schema.TypeMap,
			Required:    true,
			MinItems:    1,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"name": {
						Description: "The name of the role.",
						Type:        schema.TypeString,
						Required:    true,
						ForceNew:    true,
					},
					"applications": {
						Description: "A list of application privilege entries.",
						Type:        schema.TypeSet,
						Optional:    true,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"application": {
									Description: "The name of the application to which this entry applies.",
									Type:        schema.TypeString,
									Required:    true,
								},
								"privileges": {
									Description: "A list of strings, where each element is the name of an application privilege or action.",
									Type:        schema.TypeSet,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
									Required: true,
								},
								"resources": {
									Description: "A list resources to which the privileges are applied.",
									Type:        schema.TypeSet,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
									Required: true,
								},
							},
						},
					},
					"global": {
						Description:      "An object defining global privileges.",
						Type:             schema.TypeString,
						Optional:         true,
						ValidateFunc:     validation.StringIsJSON,
						DiffSuppressFunc: utils.DiffJsonSuppress,
					},
					"cluster": {
						Description: "A list of cluster privileges. These privileges define the cluster level actions that users with this role are able to execute.",
						Type:        schema.TypeSet,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
						Optional: true,
					},
					"indices": {
						Description: "A list of indices permissions entries.",
						Type:        schema.TypeSet,
						Optional:    true,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"field_security": {
									Description: "The document fields that the owners of the role have read access to.",
									Type:        schema.TypeList,
									Optional:    true,
									MaxItems:    1,
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											"grant": {
												Description: "List of the fields to grant the access to.",
												Type:        schema.TypeSet,
												Optional:    true,
												Elem: &schema.Schema{
													Type: schema.TypeString,
												},
											},
											"except": {
												Description: "List of the fields to which the grants will not be applied.",
												Type:        schema.TypeSet,
												Optional:    true,
												Elem: &schema.Schema{
													Type: schema.TypeString,
												},
											},
										},
									},
								},
								"names": {
									Description: "A list of indices (or index name patterns) to which the permissions in this entry apply.",
									Type:        schema.TypeSet,
									Required:    true,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
								"privileges": {
									Description: "The index level privileges that the owners of the role have on the specified indices.",
									Type:        schema.TypeSet,
									Required:    true,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
								"query": {
									Description:      "A search query that defines the documents the owners of the role have read access to.",
									Type:             schema.TypeString,
									ValidateFunc:     validation.StringIsJSON,
									DiffSuppressFunc: utils.DiffJsonSuppress,
									Optional:         true,
								},
							},
						},
					},
					"metadata": {
						Description:      "Optional meta-data.",
						Type:             schema.TypeString,
						Optional:         true,
						Computed:         true,
						ValidateFunc:     validation.StringIsJSON,
						DiffSuppressFunc: utils.DiffJsonSuppress,
					},
					"run_as": {
						Description: "A list of users that the owners of this role can impersonate.",
						Type:        schema.TypeSet,
						Optional:    true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
				},
			},
		},
		"expiration": {
			Description: "Expiration time for the API key. By default, API keys never expire.",
			Type:        schema.TypeString,
			Optional:    true,
		},
		"metadata": {
			Description:      "Arbitrary metadata that you want to associate with the API key.",
			Type:             schema.TypeString,
			Optional:         true,
			Computed:         true,
			ValidateFunc:     validation.StringIsJSON,
			DiffSuppressFunc: utils.DiffJsonSuppress,
		},
	}

	utils.AddConnectionSchema(apikeySchema)

	return &schema.Resource{
		Description: "Creates an API key for access without requiring basic authentication. See, https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html",

		CreateContext: resourceSecurityApiKeyPut,
		UpdateContext: resourceSecurityApiKeyPut,
		ReadContext:   resourceSecurityApiKeyRead,
		DeleteContext: resourceSecurityApiKeyDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: apikeySchema,
	}
}

func resourceSecurityApiKeyPut(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := clients.NewApiClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	nameId := d.Get("name").(string)
	id, diags := client.ID(nameId)
	if diags.HasError() {
		return diags
	}

	var apikey models.ApiKey
	apikey.Name = nameId

	if v, ok := d.GetOk("expiration"); ok {
		apikey.Expiration = v.(string)
	}

	if v, ok := d.GetOk("role_descriptors"); ok {
		role_descriptors := make(map[string]models.Role)
		if err := json.NewDecoder(strings.NewReader(v.(string))).Decode(&role_descriptors); err != nil {
			return diag.FromErr(err)
		}
		apikey.RolesDescriptors = role_descriptors
	}

	if v, ok := d.GetOk("metadata"); ok {
		metadata := make(map[string]interface{})
		if err := json.NewDecoder(strings.NewReader(v.(string))).Decode(&metadata); err != nil {
			return diag.FromErr(err)
		}
		apikey.Metadata = metadata
	}

	if diags := client.PutElasticsearchApiKey(&apikey); diags.HasError() {
		return diags
	}

	d.SetId(id.String())
	return resourceSecurityApiKeyRead(ctx, d, meta)
}

func resourceSecurityApiKeyRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client, err := clients.NewApiClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	compId, diags := clients.CompositeIdFromStr(d.Id())
	if diags.HasError() {
		return diags
	}
	nameId := compId.ResourceId

	apikey, diags := client.GetElasticsearchApiKey(nameId) // TODO not return ApiKey model
	if apikey == nil && diags == nil {
		d.SetId("")
		return diags
	}
	if diags.HasError() {
		return diags
	}

	metadata, err := json.Marshal(apikey.Metadata)
	if err != nil {
		return diag.FromErr(err)
	}

	// set the fields
	if err := d.Set("name", nameId); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("expiration", apikey.Expiration); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("role_descriptors", apikey.RolesDescriptors); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("metadata", string(metadata)); err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func resourceSecurityApiKeyDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client, err := clients.NewApiClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	compId, diags := clients.CompositeIdFromStr(d.Id())
	if diags.HasError() {
		return diags
	}

	if diags := client.DeleteElasticsearchApiKey(compId.ResourceId); diags.HasError() { // TODO
		return diags
	}

	d.SetId("")
	return diags
}
