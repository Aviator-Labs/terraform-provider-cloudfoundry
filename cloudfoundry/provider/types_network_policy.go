package provider

import (
	"fmt"
	"strconv"
	"strings"

	"code.cloudfoundry.org/policy_client"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type networkPolicyType struct {
	Policies legacyNetworkPoliciesSlice `tfsdk:"policies"`

	AppId       types.String `tfsdk:"app_id"`
	TargetAppId types.String `tfsdk:"target_app_id"`
	FromPort    types.Int64  `tfsdk:"from_port"`
	ToPort      types.Int64  `tfsdk:"to_port"`
	IPProtocol  types.String `tfsdk:"ip_protocol"`
}

type legacyNetworkPoliciesSlice []legacyNetworkPolicyType

type legacyNetworkPolicyType struct {
	SourceApp      types.String `tfsdk:"source_app"`
	DestinationApp types.String `tfsdk:"destination_app"`
	Port           types.String `tfsdk:"port"`
	Protocol       types.String `tfsdk:"protocol"`
}

func (data *networkPolicyType) mapToPolicyClientPolicies() ([]policy_client.Policy, diag.Diagnostics) {
	var diags diag.Diagnostics

	if !data.AppId.IsNull() && !data.AppId.IsUnknown() {
		mappedPolicy := policy_client.Policy{
			Source: policy_client.Source{
				ID: data.AppId.ValueString(),
			},
			Destination: policy_client.Destination{
				ID:       data.TargetAppId.ValueString(),
				Protocol: data.IPProtocol.ValueString(),
				Ports: policy_client.Ports{
					Start: int(data.FromPort.ValueInt64()),
					End:   int(data.ToPort.ValueInt64()),
				},
			},
		}
		return []policy_client.Policy{mappedPolicy}, diags
	}

	if len(data.Policies) > 0 {
		return data.Policies.mapToLegacyPolicyClientPolicies()
	}

	return nil, diags
}

func (policies legacyNetworkPoliciesSlice) mapToLegacyPolicyClientPolicies() ([]policy_client.Policy, diag.Diagnostics) {
	var diags diag.Diagnostics
	var mapped []policy_client.Policy

	for _, p := range policies {
		start, end, err := portRangeParse(p.Port.ValueString())
		if err != nil {
			diags.AddError("Error parsing port range", err.Error())
			return nil, diags
		}
		mapped = append(mapped, policy_client.Policy{
			Source: policy_client.Source{
				ID: p.SourceApp.ValueString(),
			},
			Destination: policy_client.Destination{
				ID:       p.DestinationApp.ValueString(),
				Protocol: p.Protocol.ValueString(),
				Ports: policy_client.Ports{
					Start: start,
					End:   end,
				},
			},
		})
	}
	return mapped, diags
}

func portRangeParse(portRange string) (start int, end int, err error) {
	portRangeSplit := strings.Split(portRange, "-")
	if len(portRangeSplit) > 2 {
		return 0, 0, fmt.Errorf("invalid range")
	}
	start, err = strconv.Atoi(portRangeSplit[0])
	if err != nil {
		return 0, 0, err
	}
	if len(portRangeSplit) == 1 {
		return start, start, nil
	}
	end, err = strconv.Atoi(portRangeSplit[1])
	if err != nil {
		return 0, 0, err
	}
	return start, end, nil
}

func mapPolicyClientPoliciesToNetworkPoliciesSlice(policies []policy_client.Policy) legacyNetworkPoliciesSlice {
	var mapped legacyNetworkPoliciesSlice

	for _, p := range policies {
		port := strconv.Itoa(p.Destination.Ports.Start)
		if p.Destination.Ports.Start != p.Destination.Ports.End {
			port = fmt.Sprintf("%d-%d", p.Destination.Ports.Start, p.Destination.Ports.End)
		}
		mapped = append(mapped, legacyNetworkPolicyType{
			SourceApp:      types.StringValue(p.Source.ID),
			DestinationApp: types.StringValue(p.Destination.ID),
			Protocol:       types.StringValue(p.Destination.Protocol),
			Port:           types.StringValue(port),
		})
	}
	return mapped
}
