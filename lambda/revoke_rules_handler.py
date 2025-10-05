import boto3
import json
from botocore.exceptions import ClientError
import logging

# Configure logging for auditable output (CA-7)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    # 1. Extract Security Group ID
    sg_id = None
    if isinstance(event, dict):
        # Handle input from SSM Automation, which passes resourceId as part of the payload
        sg_id = event.get('resourceId') or event.get('detail', {}).get('resourceId')
    
    if not sg_id:
        logger.error("Missing Security Group ID in event payload.")
        return {"statusCode": 400, "body": "Missing Security Group ID"}

    # 2. Describe SG and Handle API Errors
    try:
        resp = ec2.describe_security_groups(GroupIds=[sg_id])
        sg = resp["SecurityGroups"][0]
    except ClientError as e:
        logger.error(f"DescribeSecurityGroups failed for {sg_id}: {e}")
        # Re-raise to signal a Lambda failure, triggering SSM retry if configured
        raise

    # List to hold non-compliant rules to be revoked
    ip_permissions_to_revoke = []
    
    # 3. Iterate through rules and identify non-compliant SSH/RDP rules
    for p in sg.get("IpPermissions", []):
        proto = p.get("IpProtocol")
        from_port = p.get("FromPort")
        to_port = p.get("ToPort")
        
        # Check for target ports and protocols
        is_ssh = (from_port == 22 and to_port == 22 and proto in ['tcp', '-1'])
        is_rdp = (from_port == 3389 and to_port == 3389 and proto in ['tcp', '-1'])
        # Handle the rare case of ALL protocols ("-1" or "all")
        all_traffic_proto = (proto == "-1" and from_port is None) 
        
        if not (is_ssh or is_rdp or all_traffic_proto):
            continue

        # Check IPv4 ranges for 0.0.0.0/0 (AC-4, SC-7 violation)
        for r in p.get("IpRanges", []):
            if r.get("CidrIp") == "0.0.0.0/0":
                # Special handling for "All Traffic" rule: explicitly revoke 22 and 3389 rules
                if all_traffic_proto:
                    ip_permissions_to_revoke.extend([
                        {"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]},
                        {"IpProtocol":"tcp","FromPort":3389,"ToPort":3389,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]},
                    ])
                # Standard SSH/RDP rule: revoke the specific rule found
                else:
                    ip_permissions_to_revoke.append({"IpProtocol":proto,"FromPort":from_port,"ToPort":to_port,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]})

        # Check IPv6 ranges for ::/0 (AC-4, SC-7 violation)
        for r6 in p.get("Ipv6Ranges", []):
            if r6.get("CidrIpv6") == "::/0":
                if all_traffic_proto:
                    ip_permissions_to_revoke.extend([
                        {"IpProtocol":"tcp","FromPort":22,"ToPort":22,"Ipv6Ranges":[{"CidrIpv6":"::/0"}]},
                        {"IpProtocol":"tcp","FromPort":3389,"ToPort":3389,"Ipv6Ranges":[{"CidrIpv6":"::/0"}]},
                    ])
                else:
                    ip_permissions_to_revoke.append({"IpProtocol":proto,"FromPort":from_port,"ToPort":to_port,"Ipv6Ranges":[{"CidrIpv6":"::/0"}]})

    if not ip_permissions_to_revoke:
        logger.info("No non-compliant rules found.")
        return {"statusCode":200,"body":"Compliant"}

    # Deduplicate rules before revocation to avoid API errors
    # (using a dictionary comprehension for quick key-based uniqueness)
    def key(p):
        return (p["IpProtocol"], p.get("FromPort"), p.get("ToPort"),
                tuple(sorted([r.get("CidrIp") for r in p.get("IpRanges", []) if "CidrIp" in r])),
                tuple(sorted([r.get("CidrIpv6") for r in p.get("Ipv6Ranges", []) if "CidrIpv6" in r])))
    
    unique_permissions = list({key(p):p for p in ip_permissions_to_revoke}.values())
    
    # 4. Perform the Revocation (Decisive Enforcement)
    try:
        ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=unique_permissions)
        logger.info(f"Revoked {len(unique_permissions)} rule(s) on {sg_id}. RMF control enforced.")
        return {"statusCode":200,"body":"Remediation successful"}
        
    except ClientError as e:
        # Gracefully handle the case where the rule was already removed (e.g., race condition)
        if e.response["Error"]["Code"] == "InvalidPermission.NotFound":
            logger.warning(f"Rules already removed for {sg_id}.")
            return {"statusCode":200,"body":"Already remediated"}
            
        logger.error(f"Revoke failed for {sg_id}: {e}")
        raise