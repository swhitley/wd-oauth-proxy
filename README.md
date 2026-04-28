"""# WD OAuth 2.0 Proxy

## Introduction

The **WD OAuth 2.0 Proxy** is a highly resilient, serverless Node.js middleware service designed to securely broker OAuth 2.0 token exchanges. It sits exactly between enterprise platforms (such as Workday Extend, Studio, and Orchestrate) and external downstream Identity Providers (IdPs) or APIs.

### Why is this important?
In modern enterprise architectures, integrating core business systems with external services requires robust security and fault tolerance. Building direct authentication flows from an ERP or HR system to external APIs often presents significant challenges:

1. **Centralized Secret Management:** Storing raw client secrets, basic auth credentials, or private keys directly inside enterprise platforms creates a fragmented security posture. This proxy centralizes all sensitive credentials in Google Secret Manager (GSM), ensuring zero-trust principles and allowing security teams to rotate keys without deploying code changes to the core ERP.
2. **Keyless Architecture:** For JWT-based authentication, this proxy leverages GCP IAM to cryptographically sign assertions. This means the private keys are never exposed to the application's memory, eliminating an entire class of exfiltration vulnerabilities.
3. **Resiliency and State Management:** Enterprise APIs are subject to rate limits and transient network blips. Direct integrations often fail silently or crash under load. This proxy acts as a shock absorber, implementing intelligent token caching to prevent IdP quota exhaustion (cache stampedes) and utilizing exponential backoff with randomized jitter to gracefully handle downstream outages.
4. **Network Perimeter Enforcement:** It provides a strict boundary, validating inbound traffic against explicit IP allowlists and preventing Server-Side Request Forgery (SSRF) by validating outbound target URLs against an approved domain list.

By offloading the complexities of token acquisition, caching, and network retries to this proxy, enterprise developers can focus entirely on business logic while relying on a secure, hardened authentication bridge.

---

## Architecture & Security Posture

This proxy is built for zero-trust environments and relies on multi-layered security:
1. **Network Perimeter:** Validates inbound traffic against explicit IP allowlists.
2. **SSRF Prevention:** Validates downstream target identity providers against a strict domain allowlist.
3. **Secret Manager Integration:** Credentials are dynamically fetched from Google Secret Manager (GSM) and temporarily cached in memory to prevent cache stampedes.
4. **Keyless JWT Signing:** For the `jwt_bearer` strategy, the proxy uses GCP IAM Service Account credentials to cryptographically sign assertions without ever exposing private keys to the application's memory.

## Prerequisites

* **Node.js**: `>= 20.0.0`
* **Infrastructure**: Google Cloud Platform (GCP) Cloud Functions (or Cloud Run).
* **Network**: Configured VPC connector if egress traffic needs to be routed through a static IP.

---

## 1. Installation & Local Development

Clone the repository and install dependencies:

```
```text?code_stdout&code_event_index=2
README-v2.md generated successfully.

```bash
npm install
```

To run the function locally using the Google Cloud Functions Framework:

```bash
npm start
```
*Note: Local development requires you to authenticate with GCP via `gcloud auth application-default login` so the application can resolve Secret Manager and IAM bindings.*

---

## 2. Infrastructure Configuration (GCP)

### Required IAM Roles
The Service Account executing this function requires the following IAM permissions to operate securely:

* `roles/secretmanager.secretAccessor`: Required to fetch client secrets and target configurations from Google Secret Manager.
* `roles/iam.serviceAccountTokenCreator`: Required **only** if using the `jwt_bearer` strategy. This allows the proxy to sign JWT assertions using its own service account identity.

### Environment Variables
The application relies on specific environment variables for runtime configuration:

| Variable | Description | Default | Required |
| :--- | :--- | :--- | :--- |
| `ALLOWED_WORKDAY_IPS` | Comma-separated list of CIDR blocks for inbound traffic. | *None* | Yes |
| `GSM_CACHE_TTL_MS` | Milliseconds to cache secrets in memory to prevent GSM quota exhaustion. | `300000` (5 mins) | No |
| `GOOGLE_CLOUD_PROJECT` | Automatically injected by GCP serverless environments. Used for trace logging. | *Injected* | No |

---

## 3. Secret Manager Configuration

The proxy dynamically resolves routing, target URLs, and credentials based on a single JSON payload stored in Google Secret Manager under the secret name: **`PROXY_CREDENTIALS`**.

### `PROXY_CREDENTIALS` JSON Schema Contract

You must structure your secret exactly as follows. The root keys represent the isolated environments or target integrations.

```json
{
  "integration_name_prd": {
    "target_url": "[https://idp.example.com/oauth/token](https://idp.example.com/oauth/token)",
    "client_id": "your-client-id-here",
    "client_secret": "your-super-secret-value",
    "strategy": "client_credentials",
    "scope": "api.read"
  },
  "integration_name_dev": {
    "target_url": "[https://dev.idp.example.com/oauth/token](https://dev.idp.example.com/oauth/token)",
    "client_id": "your-dev-client-id",
    "strategy": "jwt_bearer",
    "scope": "api.read api.write"
  }
}
```

#### Field Definitions:
* `target_url` (Required): The strict HTTPS endpoint of the downstream identity provider. This MUST match your configured `ALLOWED_TARGET_HOSTS` allowlist.
* `client_id` (Required): The identifier used to match the inbound Basic Auth request to this specific configuration block.
* `client_secret` (Conditional): Required for `client_credentials`. Ignored for `jwt_bearer`.
* `strategy` (Required): Must be either `client_credentials` or `jwt_bearer`.
* `scope` (Optional): Space-separated list of OAuth scopes to request from the downstream provider.

---

## 4. Usage & Flow

Downstream enterprise systems invoke this proxy via an HTTP POST request. The proxy expects the `client_id` and a predefined proxy authentication token (not the actual IdP secret) to be passed via standard Basic Auth.

**Request Format:**
```http
POST /oauthProxy HTTP/1.1
Host: your-cloud-function-url.a.run.app
Authorization: Basic <base64(client_id:proxy_secret)>
```

**Execution Flow:**
1. The proxy decodes the Basic Auth header to extract the `client_id` and the `proxy_secret`.
2. It queries `PROXY_CREDENTIALS` in Secret Manager to find the configuration block matching the `client_id`.
3. It performs a constant-time cryptographic comparison between the provided `proxy_secret` and the expected secret to prevent timing attacks.
4. It resolves the requested `strategy` (e.g., Client Credentials vs. JWT Bearer).
5. It invokes the downstream `target_url` using an HTTP client equipped with exponential backoff and randomized jitter to handle transient network instability.
6. The resulting downstream OAuth token is returned to the caller.

---

## 5. Resiliency & Maintenance

* **Rate Limiting:** In-flight concurrent requests for the same token are bundled to prevent cache stampedes against the downstream IdP.
* **Failover Backoff:** If Google Secret Manager fails to initialize, the proxy applies a strict 5-second backoff to prevent looping initialization errors.
* **Audit Logging:** All transactions are logged using GCP structured logging, including the `traceId` to allow for end-to-end distributed tracing of failed token exchanges.
"""

with open("README-v2.md", "w") as f:
    f.write(markdown_content)
print("README-v2.md generated successfully.")

```
