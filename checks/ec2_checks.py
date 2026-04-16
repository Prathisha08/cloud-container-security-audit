import boto3

HIGH_RISK_PORTS = [22, 3389]
WEB_PORTS = [80, 443]

def check_open_security_groups():
    ec2 = boto3.client("ec2", region_name="ap-south-1")
    findings = []

    response = ec2.describe_security_groups()

    for sg in response["SecurityGroups"]:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "N/A")

        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            ip_protocol = perm.get("IpProtocol")
            ip_ranges = perm.get("IpRanges", [])

            for ip in ip_ranges:
                if ip.get("CidrIp") == "0.0.0.0/0":
                    if ip_protocol == "-1":
                        port_text = "all ports"
                        severity = "Critical"
                        recommendation = "Do not allow all traffic from the internet."
                    elif from_port in HIGH_RISK_PORTS:
                        port_text = str(from_port)
                        severity = "High"
                        recommendation = "Restrict administrative access to trusted IP addresses only."
                    elif from_port in WEB_PORTS:
                        port_text = str(from_port)
                        severity = "Medium"
                        recommendation = "Allow only if this is intentionally a public web service."
                    elif from_port is not None and to_port is not None and from_port != to_port:
                        port_text = f"{from_port}-{to_port}"
                        severity = "High"
                        recommendation = "Review whether this port range really needs public access."
                    else:
                        port_text = str(from_port) if from_port is not None else "unknown"
                        severity = "High"
                        recommendation = "Restrict access to trusted IP ranges."

                    findings.append({
                        "service": "EC2",
                        "resource": sg_id,
                        "resource_name": sg_name,
                        "issue": f"Security group open to internet on port(s): {port_text}",
                        "severity": severity,
                        "recommendation": recommendation
                    })

    return findings
