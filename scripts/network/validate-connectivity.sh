#!/usr/bin/env bash
# scripts/network/validate-connectivity.sh
# Validates Transit Gateway attachment and network connectivity between
# Development Account (agentcorevpc) and Networking Account Hub VPCs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Source load-env if available
if [ -f "${PROJECT_ROOT}/scripts/common/load-env.sh" ]; then
    source "${PROJECT_ROOT}/scripts/common/load-env.sh"
fi

TGW_ID="${1:-${CDK_TRANSIT_GATEWAY_ID:-tgw-0b86b660bfb0073c6}}"
REGION="${AWS_REGION:-${CDK_AWS_REGION:-us-west-2}}"

echo "============================================================"
echo "Transit Gateway Cross-Account Connectivity Validator"
echo "============================================================"
echo "Region:             ${REGION}"
echo "Transit Gateway ID: ${TGW_ID}"
echo ""

# 1. Check Caller Identity
echo "1. Checking AWS Caller Identity in current session..."
CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null || true)
if [ -z "${CALLER_IDENTITY}" ]; then
    echo "⚠️  Unable to call AWS CLI. Ensure AWS credentials (AWS_PROFILE or keys) are configured."
    echo "   Example: export AWS_PROFILE=achd-development"
    exit 1
fi

ACCOUNT_ID=$(echo "${CALLER_IDENTITY}" | grep -o '"Account": "[^"]*' | cut -d'"' -f4)
echo "   Connected Account: ${ACCOUNT_ID}"
echo ""

# 2. Check TGW VPC Attachment in this account
echo "2. Checking Transit Gateway VPC Attachment status..."
ATTACHMENTS=$(aws ec2 describe-transit-gateway-vpc-attachments \
    --region "${REGION}" \
    --filters "Name=transit-gateway-id,Values=${TGW_ID}" \
    --output json 2>/dev/null || true)

ATTACHMENT_COUNT=$(echo "${ATTACHMENTS}" | grep -o '"TransitGatewayAttachmentId":' | wc -l | tr -d ' ' || echo "0")

if [ "${ATTACHMENT_COUNT}" -eq "0" ]; then
    echo "⚠️  No Transit Gateway VPC Attachment found for TGW ${TGW_ID} in this account."
    echo "   Ensure the CDK stack has been deployed with CDK_TRANSIT_GATEWAY_ID set."
else
    echo "   Found ${ATTACHMENT_COUNT} attachment(s):"
    echo "${ATTACHMENTS}" | grep -E '"TransitGatewayAttachmentId"|"VpcId"|"State"' | tr -d '",' || true
fi
echo ""

# 3. Check Route Tables in Development VPC for TGW routes
echo "3. Inspecting Route Tables for TGW routes (${TGW_ID})..."
ROUTES=$(aws ec2 describe-route-tables \
    --region "${REGION}" \
    --filters "Name=route.transit-gateway-id,Values=${TGW_ID}" \
    --output json 2>/dev/null || true)

ROUTE_COUNT=$(echo "${ROUTES}" | grep -o '"RouteTableId":' | wc -l | tr -d ' ' || echo "0")
echo "   Found ${ROUTE_COUNT} route table(s) containing active routes to ${TGW_ID}."
echo ""

# 4. Networking Account Checklist
echo "============================================================"
echo "Cross-Account Hub Checklist (Execute in ACHD Networking Account):"
echo "============================================================"
cat << 'EOF'
[ ] 1. AWS RAM: TGW tgw-0b86b660bfb0073c6 is shared with ACHD Development account.
[ ] 2. Attachment State: Attachment is in "available" state (accepted if auto-accept was disabled).
       Command: aws ec2 describe-transit-gateway-vpc-attachments --region us-west-2
[ ] 3. TGW Route Table: Development VPC CIDR (e.g. 10.0.0.0/16) is propagated or associated in TGW route table.
       Command: aws ec2 get-transit-gateway-route-table-propagations --transit-gateway-attachment-id <ATTACHMENT_ID>
[ ] 4. Return Routes in Networking VPCs:
       - VPC Production (vpc-06002ae28672885e4, subnet-0d6a38a50d355ce9e, 10.130.1.0/24) route table has:
         Destination: 10.0.0.0/16 -> Target: tgw-0b86b660bfb0073c6
       - VPC Development (vpc-0626bd59839051512, subnet-0eb3fe3b999386024, 10.130.2.0/24) route table has:
         Destination: 10.0.0.0/16 -> Target: tgw-0b86b660bfb0073c6
[ ] 5. Security Groups / Firewalls:
       - Allow inbound traffic from 10.0.0.0/16 on target instances / ENIs.

Testing connectivity once targets exist:
 - Ping / ICMP: ping <TARGET_IP_IN_NETWORKING>
 - TCP Port Check: nc -zv <TARGET_IP_IN_NETWORKING> <PORT>
 - AWS VPC Reachability Analyzer:
   aws ec2 create-network-insights-path \
     --source <DEV_ENI_OR_INSTANCE_ID> \
     --destination <NETWORKING_ENI_OR_INSTANCE_ID> \
     --protocol tcp --destination-port 80
EOF
echo "============================================================"
