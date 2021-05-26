import io
import json
import logging
import dns.resolver
import os
import oci

from fdk import response

nsg_id = os.getenv("nsg_ocid")
cidr = "/32"
def update_nsg(network_client, network_security_group_id, destip):
    update_nsg_response = network_client.add_network_security_group_security_rules(network_security_group_id=nsg_id,
        add_network_security_group_security_rules_details=oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
        security_rules=[
            oci.core.models.AddSecurityRuleDetails(
                direction="EGRESS",
                protocol="6",
                description="FQDN2NSG-SecurityRule (Automated Creation)",
                destination=(destip.address + cidr),
                destination_type="CIDR_BLOCK",
                is_stateless=False,
                source="0.0.0.0/0",
                source_type="CIDR_BLOCK",
                tcp_options=oci.core.models.TcpOptions(
                    destination_port_range=oci.core.models.PortRange(
                        max=443,
                        min=443
                    )
                )
            )
        ]
        )
    ).data
    return update_nsg_response
    

#def resolvefqdn()

def handler(ctx, data: io.BytesIO = None):

    signer = oci.auth.signers.get_resource_principals_signer()
    network_client = oci.core.VirtualNetworkClient(config={}, signer=signer)

    name = os.getenv("fqdn2resolve")
    network_security_group_id = os.getenv("nsg_ocid")
    result = []
    try:
        answers = dns.resolver.query(name, 'A')
        for destip in answers:
             update_resp = update_nsg(network_client, network_security_group_id, destip)
             result.append(destip.address)
        return result

    except (Exception, ValueError) as ex:
        logging.getLogger().info('error resolving name: ' + str(ex))

    logging.getLogger().info("FQDN2RESOLVER execution")
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": "Resolved Ip is {0}".format(result)}),
        headers={"Content-Type": "application/json"}
    )
