import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

import { AppConfig, getResourceName, getRemovalPolicy } from '../../config';

export interface CognitoConstructProps {
  config: AppConfig;
}

/**
 * CognitoConstruct — Cognito user pool, BFF app client, hosted UI domain.
 *
 * Central identity broker for all authentication. Federates to external
 * IdPs (Entra ID, Okta, Google) and issues its own JWTs. Self-signup is
 * enabled initially for first-boot; the App API disables it after the
 * first admin user is created.
 *
 * The BFF App Client is a confidential client used by app-api for the
 * server-side OAuth token exchange in the Token Handler BFF flow. The
 * client secret authenticates the /oauth2/token call from app-api; the
 * secret never leaves the server. The public PKCE SPA client that
 * previously sat alongside this one was retired in Phase 7 when the SPA
 * cut over fully to cookie auth.
 *
 * Federated IdPs are configured on the user pool out-of-band today and
 * listed here by ProviderName via `config.cognito.supportedIdentityProviders`.
 * COGNITO is always included so username/password sign-in keeps working
 * alongside SSO.
 */
export class CognitoConstruct extends Construct {
  public readonly userPool: cognito.UserPool;
  public readonly bffAppClient: cognito.UserPoolClient;
  public readonly bffAppClientSecret: secretsmanager.Secret;
  public readonly cognitoDomain: cognito.UserPoolDomain;
  public readonly n8nAppClient?: cognito.UserPoolClient;
  public readonly n8nAppClientSecret?: secretsmanager.Secret;
  public readonly entraIdp?: cognito.UserPoolIdentityProviderOidc;

  constructor(scope: Construct, id: string, props: CognitoConstructProps) {
    super(scope, id);

    const { config } = props;

    this.userPool = new cognito.UserPool(this, 'CognitoUserPool', {
      userPoolName: getResourceName(config, 'user-pool'),
      // ESSENTIALS is required for access-token customization via the
      // Pre-Token-Generation v2 trigger (the MCP identity-forwarding feature,
      // docs/specs/MCP_USER_IDENTITY_FORWARDING_SPEC.md). Set explicitly so a
      // fresh fork's pool comes up on a plan that supports the trigger before
      // TokenEnrichmentConstruct attaches it. Existing pools are already on
      // ESSENTIALS, so this is a no-op for current deployments. The feature
      // itself stays opt-in (default off) — this only guarantees capability.
      featurePlan: cognito.FeaturePlan.ESSENTIALS,
      selfSignUpEnabled: true,
      signInAliases: { username: true, email: true },
      autoVerify: { email: true },
      standardAttributes: {
        email: { required: true, mutable: true },
        givenName: { mutable: true },
        familyName: { mutable: true },
      },
      customAttributes: {
        provider_sub: new cognito.StringAttribute({ mutable: true }),
        roles: new cognito.StringAttribute({ mutable: true }),
      },
      passwordPolicy: {
        minLength: config.cognito.passwordMinLength || 8,
        requireUppercase: true,
        requireLowercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: getRemovalPolicy(config),
    });

    // Entra ID OIDC Identity Provider (dev infrastructure or explicit config)
    const entraConfig = config.cognito.entraId;
    const hasEntraConfig = Boolean(
      entraConfig?.clientId &&
      entraConfig?.clientSecret &&
      (entraConfig?.tenantId || entraConfig?.issuerUrl),
    );

    if (hasEntraConfig) {
      const issuer =
        entraConfig!.issuerUrl ||
        `https://login.microsoftonline.com/${entraConfig!.tenantId}/v2.0`;
      const providerName = entraConfig!.providerName || 'ms-entra-id';

      this.entraIdp = new cognito.UserPoolIdentityProviderOidc(
        this,
        'EntraOidcProvider',
        {
          userPool: this.userPool,
          name: providerName,
          clientId: entraConfig!.clientId!,
          clientSecret: entraConfig!.clientSecret!,
          issuerUrl: issuer,
          scopes: ['openid', 'profile', 'email'],
          attributeRequestMethod: cognito.OidcAttributeRequestMethod.GET,
          attributeMapping: {
            email: cognito.ProviderAttribute.other('email'),
            givenName: cognito.ProviderAttribute.other('given_name'),
            familyName: cognito.ProviderAttribute.other('family_name'),
            custom: {
              provider_sub: cognito.ProviderAttribute.other('sub'),
            },
          },
        },
      );
    }

    const bffCallbackUrls = config.domainName
      ? [`https://${config.domainName}/api/auth/callback`]
      : ['http://localhost:8000/auth/callback'];
    const bffLogoutUrls = config.domainName
      ? [`https://${config.domainName}`]
      : ['http://localhost:4200'];

    if (config.cognito.callbackUrls) {
      bffCallbackUrls.push(...config.cognito.callbackUrls);
    }
    if (config.cognito.logoutUrls) {
      bffLogoutUrls.push(...config.cognito.logoutUrls);
    }

    const bffSupportedIdentityProviders: cognito.UserPoolClientIdentityProvider[] =
      [
        cognito.UserPoolClientIdentityProvider.COGNITO,
        ...(config.cognito.supportedIdentityProviders ?? [])
          .filter((name) => name !== 'COGNITO')
          .map((name) =>
            cognito.UserPoolClientIdentityProvider.custom(name),
          ),
      ];

    if (this.entraIdp) {
      const providerName = entraConfig?.providerName || 'ms-entra-id';
      if (!bffSupportedIdentityProviders.some((p) => p.name === providerName)) {
        bffSupportedIdentityProviders.push(
          cognito.UserPoolClientIdentityProvider.custom(providerName),
        );
      }
    }

    this.bffAppClient = this.userPool.addClient('CognitoBFFAppClient', {
      userPoolClientName: getResourceName(config, 'bff-app-client'),
      generateSecret: true,
      authFlows: { userSrp: false, custom: false },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.PROFILE,
          cognito.OAuthScope.EMAIL,
        ],
        callbackUrls: bffCallbackUrls,
        logoutUrls: bffLogoutUrls,
      },
      preventUserExistenceErrors: true,
      supportedIdentityProviders: bffSupportedIdentityProviders,
    });

    if (this.entraIdp) {
      this.bffAppClient.node.addDependency(this.entraIdp);
    }

    this.bffAppClientSecret = new secretsmanager.Secret(
      this,
      'CognitoBFFAppClientSecret',
      {
        secretName: getResourceName(config, 'cognito-bff-app-client-secret'),
        description:
          'Client secret for the Cognito BFF app client (Token Handler flow)',
        secretStringValue: this.bffAppClient.userPoolClientSecret,
        removalPolicy: getRemovalPolicy(config),
      },
    );

    // Dedicated App Client for n8n ALB authentication
    if (config.cognito.n8nAlbAuth?.enabled) {
      const n8nCallbackUrls = config.cognito.n8nAlbAuth.callbackUrls?.length
        ? config.cognito.n8nAlbAuth.callbackUrls
        : config.domainName
          ? [`https://n8n.${config.domainName}/oauth2/idpresponse`]
          : ['https://localhost:5678/oauth2/idpresponse'];

      const n8nLogoutUrls = config.cognito.n8nAlbAuth.logoutUrls?.length
        ? config.cognito.n8nAlbAuth.logoutUrls
        : config.domainName
          ? [`https://n8n.${config.domainName}`]
          : ['https://localhost:5678'];

      const n8nSupportedIdps: cognito.UserPoolClientIdentityProvider[] = [
        cognito.UserPoolClientIdentityProvider.COGNITO,
        ...(config.cognito.supportedIdentityProviders ?? [])
          .filter((name) => name !== 'COGNITO')
          .map((name) =>
            cognito.UserPoolClientIdentityProvider.custom(name),
          ),
      ];

      if (this.entraIdp) {
        const providerName = entraConfig?.providerName || 'ms-entra-id';
        if (!n8nSupportedIdps.some((p) => p.name === providerName)) {
          n8nSupportedIdps.push(
            cognito.UserPoolClientIdentityProvider.custom(providerName),
          );
        }
      }

      this.n8nAppClient = this.userPool.addClient('CognitoN8nAppClient', {
        userPoolClientName: getResourceName(config, 'n8n-alb-client'),
        generateSecret: true,
        authFlows: { userSrp: false, custom: false },
        oAuth: {
          flows: { authorizationCodeGrant: true },
          scopes: [
            cognito.OAuthScope.OPENID,
            cognito.OAuthScope.PROFILE,
            cognito.OAuthScope.EMAIL,
          ],
          callbackUrls: n8nCallbackUrls,
          logoutUrls: n8nLogoutUrls,
        },
        preventUserExistenceErrors: true,
        supportedIdentityProviders: n8nSupportedIdps,
      });

      if (this.entraIdp) {
        this.n8nAppClient.node.addDependency(this.entraIdp);
      }

      this.n8nAppClientSecret = new secretsmanager.Secret(
        this,
        'CognitoN8nAppClientSecret',
        {
          secretName: getResourceName(config, 'cognito-n8n-alb-client-secret'),
          description:
            'Client secret for the Cognito n8n ALB app client',
          secretStringValue: this.n8nAppClient.userPoolClientSecret,
          removalPolicy: getRemovalPolicy(config),
        },
      );

      new ssm.StringParameter(this, 'CognitoN8nAppClientIdParameter', {
        parameterName: `/${config.projectPrefix}/auth/cognito/n8n-app-client-id`,
        stringValue: this.n8nAppClient.userPoolClientId,
        description: 'Cognito n8n ALB app client ID',
        tier: ssm.ParameterTier.STANDARD,
      });

      new ssm.StringParameter(this, 'CognitoN8nAppClientSecretArnParameter', {
        parameterName: `/${config.projectPrefix}/auth/cognito/n8n-app-client-secret-arn`,
        stringValue: this.n8nAppClientSecret.secretArn,
        description: 'Cognito n8n ALB app client secret ARN',
        tier: ssm.ParameterTier.STANDARD,
      });
    }

    const defaultPrefix = (config.environment === 'development' || config.environment === 'dev')
      ? config.projectPrefix
      : `${config.projectPrefix}-${config.awsAccount}`;

    this.cognitoDomain = this.userPool.addDomain('CognitoDomain', {
      cognitoDomain: {
        domainPrefix: config.cognito.domainPrefix || defaultPrefix,
      },
    });

    // SSM publications
    new ssm.StringParameter(this, 'CognitoUserPoolIdParameter', {
      parameterName: `/${config.projectPrefix}/auth/cognito/user-pool-id`,
      stringValue: this.userPool.userPoolId,
      description: 'Cognito User Pool ID',
      tier: ssm.ParameterTier.STANDARD,
    });




    new ssm.StringParameter(this, 'CognitoBFFAppClientIdParameter', {
      parameterName: `/${config.projectPrefix}/auth/cognito/bff-app-client-id`,
      stringValue: this.bffAppClient.userPoolClientId,
      description: 'Cognito BFF (confidential) app client ID',
      tier: ssm.ParameterTier.STANDARD,
    });

  }
}
