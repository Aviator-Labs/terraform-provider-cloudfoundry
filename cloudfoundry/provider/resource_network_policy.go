package provider

import (
	"context"
	"fmt"
	"regexp"

	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/policy_client"
	"github.com/cloudfoundry/terraform-provider-cloudfoundry/cloudfoundry/provider/managers"
	"github.com/cloudfoundry/terraform-provider-cloudfoundry/internal/validation"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/samber/lo"
)

var (
	_ resource.Resource              = &NetworkPolicyResource{}
	_ resource.ResourceWithConfigure = &NetworkPolicyResource{}
)

func NewNetworkPolicyResource() resource.Resource {
	return &NetworkPolicyResource{}
}

type NetworkPolicyResource struct {
	client policy_client.ExternalPolicyClient
}

func (r *NetworkPolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_policy"
}

func (r *NetworkPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	session, ok := req.ProviderData.(*managers.Session)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *managers.Session. got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	cfg := session.CFClient.Config
	r.client = policy_client.NewExternal(lager.NewLogger("ExternalPolicyClient"), cfg.HTTPAuthClient(), cfg.ApiURL(""))
}

func (r *NetworkPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Provides a Cloud Foundry resource for managing Cloud Foundry Network Policies",

		Attributes: map[string]schema.Attribute{
			"app_id": schema.StringAttribute{
				MarkdownDescription: "The ID of the application to connect from",
				Optional:            true,
				Validators: []validator.String{
					validation.ValidUUID(),
				},
			},
			"target_app_id": schema.StringAttribute{
				MarkdownDescription: "The ID of the application to connect to",
				Optional:            true,
				Validators: []validator.String{
					validation.ValidUUID(),
				},
			},
			"from_port": schema.Int64Attribute{
				MarkdownDescription: "The start of port range for the TCP and UDP protocols",
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(1, 65535),
				},
			},
			"to_port": schema.Int64Attribute{
				MarkdownDescription: "The end of port range for the TCP and UDP protocols",
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(1, 65535),
				},
			},
			"ip_protocol": schema.StringAttribute{
				MarkdownDescription: "One of 'udp' or 'tcp' identifying the allowed protocol for the access. Default is 'tcp'.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("tcp"),
				Validators: []validator.String{
					stringvalidator.OneOf("tcp", "udp"),
				},
			},
			"policies": schema.ListNestedAttribute{
				MarkdownDescription: "Network policies to create",
				Optional:            true,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
				},
				DeprecationMessage: "The policies argument is deprecated. Use the cloudfoundry_network_policies resource instead.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"source_app": schema.StringAttribute{
							MarkdownDescription: "The ID of the application to connect from",
							Required:            true,
							Validators: []validator.String{
								validation.ValidUUID(),
							},
						},
						"destination_app": schema.StringAttribute{
							MarkdownDescription: "The ID of the application to connect to",
							Required:            true,
							Validators: []validator.String{
								validation.ValidUUID(),
							},
						},
						"port": schema.StringAttribute{
							MarkdownDescription: "Port (8080) or range of ports (8080-8085) for connection to destination app",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.Any(
									stringvalidator.RegexMatches(
										regexp.MustCompile(`^\d+$`),
										"can match a single port number",
									),
									stringvalidator.RegexMatches(
										regexp.MustCompile(`^\d+-\d+$`),
										"can match a port range",
									),
								),
							},
						},
						"protocol": schema.StringAttribute{
							MarkdownDescription: "One of 'udp' or 'tcp' identifying the allowed protocol for the access. Default is 'tcp'.",
							Optional:            true,
							Computed:            true,
							Default:             stringdefault.StaticString("tcp"),
							Validators: []validator.String{
								stringvalidator.OneOf("tcp", "udp"),
							},
						},
					},
				},
			},
		},
	}
}

func (r *NetworkPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan networkPolicyType

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := plan.mapToPolicyClientPolicies()
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.AddPolicies("", policies); err != nil {
		resp.Diagnostics.AddError(
			"API Error Creating Policies",
			"Could not create Policies : "+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, "created network policies")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NetworkPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state networkPolicyType

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := state.mapToPolicyClientPolicies()
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeletePolicies("", policies); err != nil {
		resp.Diagnostics.AddError(
			"API Error Deleting Policies",
			"Could not remove Policies : "+err.Error(),
		)
		return
	}
}

func (r *NetworkPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data networkPolicyType

	diags := req.State.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	idsMap := make(map[string]bool)
	if !data.AppId.IsNull() && !data.AppId.IsUnknown() {
		idsMap[data.AppId.ValueString()] = true
		idsMap[data.TargetAppId.ValueString()] = true
	} else {
		for _, p := range data.Policies {
			idsMap[p.SourceApp.ValueString()] = true
			idsMap[p.DestinationApp.ValueString()] = true
		}
	}

	ids := make([]string, 0, len(idsMap))
	for k := range idsMap {
		ids = append(ids, k)
	}

	if len(ids) == 0 {
		return
	}

	policies, err := r.client.GetPoliciesByID("", ids...)
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("API Error Reading network_policy %v", ids), err.Error())
		return
	}

	if !data.AppId.IsNull() && !data.AppId.IsUnknown() {
		found := lo.Filter(policies, func(p policy_client.Policy, _ int) bool {
			return p.Source.ID == data.AppId.ValueString() &&
				p.Destination.ID == data.TargetAppId.ValueString() &&
				p.Destination.Protocol == data.IPProtocol.ValueString() &&
				p.Destination.Ports.Start == int(data.FromPort.ValueInt64()) &&
				p.Destination.Ports.End == int(data.ToPort.ValueInt64())
		})

		if len(found) == 0 {
			resp.State.RemoveResource(ctx)
			return
		}
		data.Policies = nil
	} else {
		mappedPolicies := mapPolicyClientPoliciesToNetworkPoliciesSlice(policies)
		data.Policies = lo.Intersect(mappedPolicies, data.Policies)

		if len(data.Policies) == 0 {
			resp.State.RemoveResource(ctx)
			return
		}
	}

	tflog.Trace(ctx, "read a network_policy resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *NetworkPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, previousState networkPolicyType
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &previousState)...)
	if resp.Diagnostics.HasError() {
		return
	}

	oldPolicies, diags := previousState.mapToPolicyClientPolicies()
	resp.Diagnostics.Append(diags...)
	newPolicies, diags := plan.mapToPolicyClientPolicies()
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	remove, add := lo.Difference(oldPolicies, newPolicies)

	if len(remove) > 0 {
		if err := r.client.DeletePolicies("", remove); err != nil {
			resp.Diagnostics.AddError(
				"API Error Deleting Policies",
				"Could not remove old Policies during update: "+err.Error(),
			)
			return
		}
	}
	if len(add) > 0 {
		if err := r.client.AddPolicies("", add); err != nil {
			resp.Diagnostics.AddError(
				"API Error Creating Policies",
				"Could not create new Policies during update: "+err.Error(),
			)
			return
		}
	}

	tflog.Trace(ctx, "updated a network_policy resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
