// Reference Azure Container Apps deployment with an ARC sidecar.
//
// Placeholders:
//   APP_IMAGE_PLACEHOLDER          -- replace with your application image
//   ghcr.io/backbay/arc-sidecar    -- replace with the sidecar image you pushed
//   Key Vault secrets must be created before deploy; the Container Apps
//   environment's managed identity needs GET on those secrets.
//
// Deploy:
//   az deployment group create \
//     --resource-group my-rg \
//     --template-file deploy/azure/container-app.bicep \
//     --parameters location=eastus ...
//
// Startup ordering: the ARC sidecar declares a startupProbe on :9090/health;
// the app container declares a startupProbe on :8080/healthz that depends on
// the sidecar URL being reachable. The sidecar fails closed if
// ARC_KERNEL_CONFIG_PATH cannot be loaded, causing the revision to be marked
// unhealthy and recycled.

@description('Azure region for the container app.')
param location string = resourceGroup().location

@description('Name of the container app.')
param containerAppName string = 'agent-tool-server'

@description('Resource ID of the Container Apps managed environment.')
param managedEnvironmentId string

@description('Application container image (placeholder, override at deploy time).')
param appImage string = 'APP_IMAGE_PLACEHOLDER'

@description('ARC sidecar container image.')
param arcSidecarImage string = 'ghcr.io/backbay/arc-sidecar:latest'

@description('Key Vault URI that holds the ARC signing key secret.')
param arcSigningKeySecretUri string

@description('Key Vault URI that holds the capability authority URL secret.')
param arcCapabilityAuthoritySecretUri string

@description('User-assigned managed identity resource ID with Key Vault read access.')
param userAssignedIdentityId string

@description('Policy source URI (blob, file, or remote).')
param arcPolicySource string = 'https://arcconfig.blob.core.windows.net/config/policy.yaml'

@description('Receipt sink destination.')
param arcReceiptSink string = 'cosmosdb://arc-receipts'

resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: containerAppName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${userAssignedIdentityId}': {}
    }
  }
  properties: {
    managedEnvironmentId: managedEnvironmentId
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        allowInsecure: false
      }
      secrets: [
        {
          name: 'arc-signing-key'
          keyVaultUrl: arcSigningKeySecretUri
          identity: userAssignedIdentityId
        }
        {
          name: 'arc-capability-authority-url'
          keyVaultUrl: arcCapabilityAuthoritySecretUri
          identity: userAssignedIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'app'
          image: appImage
          resources: {
            cpu: json('0.75')
            memory: '1.5Gi'
          }
          env: [
            {
              name: 'ARC_SIDECAR_URL'
              value: 'http://localhost:9090'
            }
            {
              name: 'ARC_SIDECAR_HEALTH_URL'
              value: 'http://localhost:9090/health'
            }
          ]
          probes: [
            {
              type: 'Startup'
              httpGet: {
                path: '/healthz'
                port: 8080
              }
              initialDelaySeconds: 2
              periodSeconds: 2
              failureThreshold: 30
            }
            {
              type: 'Liveness'
              httpGet: {
                path: '/healthz'
                port: 8080
              }
              periodSeconds: 10
              failureThreshold: 3
            }
          ]
        }
        {
          name: 'arc-sidecar'
          image: arcSidecarImage
          // The sidecar image's CMD default is `--help`; override with
          // a long-running subcommand so the probes succeed and the
          // app container becomes ready.
          command: [
            '/usr/local/bin/arc-sidecar'
          ]
          args: [
            'api'
            'protect'
            '--upstream'
            'http://127.0.0.1:8080'
            '--listen'
            '0.0.0.0:9090'
          ]
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: [
            {
              name: 'ARC_LISTEN_ADDR'
              value: '0.0.0.0:9090'
            }
            {
              name: 'ARC_HEALTH_PATH'
              value: '/health'
            }
            {
              name: 'ARC_KERNEL_CONFIG_PATH'
              value: '/etc/arc/kernel.yaml'
            }
            {
              name: 'ARC_POLICY_SOURCE'
              value: arcPolicySource
            }
            {
              name: 'ARC_RECEIPT_SINK'
              value: arcReceiptSink
            }
            {
              name: 'ARC_LOG_LEVEL'
              value: 'info'
            }
            {
              name: 'ARC_SIGNING_KEY'
              secretRef: 'arc-signing-key'
            }
            {
              name: 'ARC_CAPABILITY_AUTHORITY_URL'
              secretRef: 'arc-capability-authority-url'
            }
          ]
          probes: [
            {
              type: 'Startup'
              httpGet: {
                path: '/health'
                port: 9090
              }
              initialDelaySeconds: 1
              periodSeconds: 1
              failureThreshold: 30
            }
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 9090
              }
              periodSeconds: 10
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health'
                port: 9090
              }
              periodSeconds: 5
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 20
        rules: [
          {
            name: 'http-scale'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

output containerAppFqdn string = containerApp.properties.configuration.ingress.fqdn
output containerAppName string = containerApp.name
