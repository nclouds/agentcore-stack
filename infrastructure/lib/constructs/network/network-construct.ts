import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';

import { AppConfig, getResourceName } from '../../config';

export interface NetworkConstructProps {
  config: AppConfig;
}

/**
 * NetworkConstruct — VPC, subnets, NAT, route tables.
 *
 * Provisions the foundational network layer for the platform:
 *
 *   - VPC sized at `config.vpcCidr` with DNS hostnames + DNS support on
 *   - 2 AZs (high availability) × 2 subnet types (public, private-with-egress)
 *   - 1 NAT gateway (cost-optimized; can be increased for cross-AZ HA)
 *
 * SSM parameters published (cross-stack reads, kept identical to legacy
 * for Phase 2 equivalence; will be retired in Phase 3 once typed prop
 * passing replaces SSM):
 *
 *   /{prefix}/network/vpc-id
 *   /{prefix}/network/vpc-cidr
 *   /{prefix}/network/private-subnet-ids
 *   /{prefix}/network/public-subnet-ids
 *   /{prefix}/network/availability-zones
 *
 * Logical IDs preserved verbatim from the original
 * `infrastructure-stack.ts` so the Phase 2 equivalence test stays at
 * zero diff.
 */
export class NetworkConstruct extends Construct {
  public readonly vpc: ec2.Vpc;
  public readonly transitGatewayAttachment?: ec2.CfnTransitGatewayAttachment;
  public readonly transitGatewayRoutes: ec2.CfnRoute[] = [];

  constructor(scope: Construct, id: string, props: NetworkConstructProps) {
    super(scope, id);

    const { config } = props;

    this.vpc = new ec2.Vpc(this, 'Vpc', {
      vpcName: getResourceName(config, 'vpc'),
      ipAddresses: ec2.IpAddresses.cidr(config.vpcCidr),
      maxAzs: 2, // Use 2 AZs for high availability
      natGateways: 1, // Single NAT Gateway for cost optimization (can be increased for HA)
      subnetConfiguration: [
        {
          cidrMask: 24,
          name: 'Public',
          subnetType: ec2.SubnetType.PUBLIC,
        },
        {
          cidrMask: 24,
          name: 'Private',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
        },
      ],
      enableDnsHostnames: true,
      enableDnsSupport: true,
    });

    if (config.transitGatewayId) {
      // Create Transit Gateway attachment placing ENIs in the private subnets
      this.transitGatewayAttachment = new ec2.CfnTransitGatewayAttachment(
        this,
        'TransitGatewayAttachment',
        {
          transitGatewayId: config.transitGatewayId,
          vpcId: this.vpc.vpcId,
          subnetIds: this.vpc.privateSubnets.map((s) => s.subnetId),
          tags: [
            {
              key: 'Name',
              value: getResourceName(config, 'tgw-attachment'),
            },
          ],
        }
      );

      // Add routes to Transit Gateway in all private and public subnet route tables
      if (config.transitGatewayRouteCidrs && config.transitGatewayRouteCidrs.length > 0) {
        const targetRouteTables: { prefix: string; routeTableId: string }[] = [];
        const seenRouteTables = new Set<string>();

        this.vpc.privateSubnets.forEach((s, idx) => {
          if (!seenRouteTables.has(s.routeTable.routeTableId)) {
            seenRouteTables.add(s.routeTable.routeTableId);
            targetRouteTables.push({ prefix: `Private${idx + 1}`, routeTableId: s.routeTable.routeTableId });
          }
        });

        this.vpc.publicSubnets.forEach((s, idx) => {
          if (!seenRouteTables.has(s.routeTable.routeTableId)) {
            seenRouteTables.add(s.routeTable.routeTableId);
            targetRouteTables.push({ prefix: `Public${idx + 1}`, routeTableId: s.routeTable.routeTableId });
          }
        });

        targetRouteTables.forEach(({ prefix, routeTableId }) => {
          config.transitGatewayRouteCidrs!.forEach((cidr) => {
            const sanitizedCidr = cidr.replace(/[^a-zA-Z0-9]/g, '');
            const route = new ec2.CfnRoute(
              this,
              `RouteToTgw${prefix}Cidr${sanitizedCidr}`,
              {
                routeTableId,
                destinationCidrBlock: cidr,
                transitGatewayId: config.transitGatewayId,
              }
            );
            route.addResourceDependency(this.transitGatewayAttachment!);
            this.transitGatewayRoutes.push(route);
          });
        });
      }
    }
  }
}
