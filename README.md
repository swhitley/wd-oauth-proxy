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

## Quick Start: Google Cloud Deployment

For a fast path to deploying the proxy, you can use the Google Cloud CLI (`gcloud`) to deploy directly to Cloud Run. 

**1. Clone & Authenticate**
```bash
git clone https://github.com/swhitley/wd-oauth-proxy
cd wd-oauth-proxy
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

**2. Enable Required APIs**
```bash
gcloud services enable run.googleapis.com secretmanager.googleapis.com
```

**3. Create Secrets**
Create your proxy credentials and at least one target configuration (e.g., for Google APIs) in Secret Manager.
```bash
echo '{"client_1": {"client_id": "proxy-user", "client_secret": "super-secret"}}' | gcloud secrets create PROXY_CREDENTIALS --data-file=-

echo '{"target_url": "https://oauth2.googleapis.com/token", "client_id": "your-sa@your-project.iam.gserviceaccount.com", "strategy": "jwt_bearer", "allowed_scopes": ["https://www.googleapis.com/auth/cloud-platform"]}' | gcloud secrets create TARGET_GOOGLE_API --data-file=-
```

**4. Deploy to Cloud Run**
Deploy the service, injecting the required environment variables.
```bash
gcloud run deploy wd-oauth-proxy \
  --source . \
  --region YOUR_REGION \
  --allow-unauthenticated \
  --set-env-vars="^|^ALLOWED_WORKDAY_IPS=35.80.211.71,35.155.167.195,44.234.22.80,44.234.22.81,44.234.22.82,44.234.22.83,54.212.47.21|ALLOWED_TARGET_HOSTS=oauth2.googleapis.com"
```
*(Note: Restrict `ALLOWED_WORKDAY_IPS` to your actual Workday tenant NAT IPs for production).*

Review the IP Addresses used by Workday Extend:  https://developer.workday.com/documentation/oas1626117162588?q=workday%20extend%20ip%20list#proxy-firewall-and-ip-addresses

Also note the IP Addresses used in your Data Center:  https://community-content.workday.com/content/workday-community/en-us/reference/get-help/support/workday-data-centers.html?lang=en-us

**5. Grant IAM Permissions**
Give your Cloud Run service identity access to read the secrets you just created, and the ability to sign tokens.
```bash
# Get the service account used by your deployment
SERVICE_ACCOUNT=$(gcloud run services describe wd-oauth-proxy --region YOUR_REGION --format="value(spec.template.spec.serviceAccountName)")

# Grant Secret Accessor
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor"

# Grant Token Creator (Required for jwt_bearer strategy)
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/iam.serviceAccountTokenCreator"
```

---

## Detailed Configuration Reference

### 1. Installation & Local Development

Clone the repository and install dependencies:

```bash
npm install
```

To run the function locally using the Google Cloud Functions Framework:

```bash
npm start
```
> **Note:** Local development requires you to authenticate with GCP via `gcloud auth application-default login` so the application can resolve Secret Manager and IAM bindings.

### 2. Infrastructure Configuration (GCP)

<img width="1361" height="692" alt="image" src="https://github.com/user-attachments/assets/ae7c8b53-354a-4de3-9a90-c166a0ff20c2" />


#### Required IAM Roles
The Service Account executing this function requires the following IAM permissions to operate securely:

* `roles/secretmanager.secretAccessor`: Required to fetch client secrets and target configurations from Google Secret Manager.
* `roles/iam.serviceAccountTokenCreator`: Required **only** if using the `jwt_bearer` strategy. This allows the proxy to sign JWT assertions using its own service account identity.

It may be difficult to identify the exact service account under which your service is executing.  The command below is helpful to identify the service account.  Apply the additional permissions to that account.

```bash
gcloud run services describe YOUR_SERVICE_NAME \
  --region YOUR_REGION \
  --format="value(spec.template.spec.serviceAccountName)"
```

#### Environment Variables
The application relies on specific environment variables for runtime configuration:

| Variable | Description | Default | Required |
| :--- | :--- | :--- | :--- |
| `ALLOWED_WORKDAY_IPS` | Comma-separated list of CIDR blocks for inbound traffic. | *None* | Yes |
| `ALLOWED_TARGET_HOSTS` | Comma-separated list of approved downstream domains to prevent SSRF. | *None* | Yes |
| `RATE_LIMIT_THRESHOLD` | Maximum permitted token requests per minute per client instance. | `100` | No |
| `GSM_CACHE_TTL_MS` | Milliseconds to cache secrets in memory to prevent GSM quota exhaustion. | `300000` (5 mins) | No |
| `GOOGLE_CLOUD_PROJECT` | Automatically injected by GCP serverless environments. Used for trace logging. | *Injected* | No |

<img width="807" height="749" alt="image" src="https://github.com/user-attachments/assets/d4330f09-3c21-4ace-b539-9261ceb830a9" />

### 3. Secret Manager Configuration

The proxy relies on a split-secret architecture to separate proxy authentication from downstream target configurations. Both configurations are securely stored in Google Secret Manager.

#### 1. `PROXY_CREDENTIALS` (Proxy Authentication)
A single JSON payload storing the accepted proxy client credentials.

The Proxy Credentials are the credentials for the WD OAuth Proxy.  As such, you generate and own these credentials.  They are not generated by some other service.  These are the credentials you enter in Workday in the External Client CredStore. Enter the client_id and client_secret as described below in the Google Secret Manager.  Then use the same credentials in Workday to authenticate from Workday to your OAuth Proxy.  The credentials to connect to other APIs, like Google, are contained in the `TARGET` configuration, shown in the next section.

```json
{
  "client_1": {
    "client_id": "your-proxy-client-id",
    "client_secret": "your-proxy-super-secret-value"
  }
}
```

#### 2. `TARGET_{target_id}` (Downstream Target Configurations)
Each downstream integration requires its own secret prefixed with `TARGET_` (e.g., `TARGET_GOOGLE_API`). 

```json
{
  "target_url": "https://oauth2.googleapis.com/token",
  "client_id": "your-downstream-client-id",
  "client_secret": "your-downstream-secret",
  "strategy": "jwt_bearer",
  "default_scope": "https://www.googleapis.com/auth/cloud-platform",
  "allowed_scopes": [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/spreadsheets"
  ]
}
```

##### Field Definitions (`TARGET_{target_id}`):
* `target_url` (Required): The strict HTTPS endpoint of the downstream IdP. This MUST match a domain in your `ALLOWED_TARGET_HOSTS` allowlist.
* `client_id` (Required): The IdP client ID or Service Account email.
* `client_secret` (Conditional): Required for `client_credentials`. Ignored for `jwt_bearer`.
* `strategy` (Required): Must be either `client_credentials` or `jwt_bearer`.
* `default_scope` (Optional): The scope to request if the client omits the scope parameter.
* `allowed_scopes` (Required): An array of explicitly permitted scopes. The proxy will reject requests for scopes not listed here with a `403 Forbidden`.

### 4. Usage & Flow

Downstream enterprise systems invoke this proxy via an HTTP POST request. The proxy expects the `client_id` and a predefined proxy authentication token to be passed via standard Basic Auth, and a `target_id` to route the request appropriately.

**Request Format:**

On Workday's External Client CredStore, the `Token Endpoint` is the critical field for the token URL.  Workday does not pass the `Scope` field, so include the scope query string variable in the Token Endpoint field.

```http
POST /token?target_id=GOOGLE_API&scope=https://www.googleapis.com/auth/spreadsheets HTTP/1.1
Host: your-cloud-function-url.a.run.app
Authorization: Basic <base64(client_id:proxy_secret)>
```
*(Note: `target_id` and `scope` can alternatively be passed as `application/x-www-form-urlencoded` or `application/json` in the POST body).*

<img width="590" height="756" alt="image" src="https://github.com/user-attachments/assets/70ffcc22-2558-4ebb-ae60-73241bd5374e" />

**Execution Flow:**
1. The proxy validates the requested `target_id` and standardizes the inbound HTTP path.
2. It decodes the Basic Auth header to extract the proxy `client_id` and `client_secret`.
3. It queries `PROXY_CREDENTIALS` in Secret Manager and performs a constant-time cryptographic comparison against the expected proxy secret to prevent timing attacks.
4. It resolves the specific `TARGET_{target_id}` configuration from Secret Manager.
5. It validates the requested `scope` against the target's `allowed_scopes` array.
6. It resolves the requested `strategy` (e.g., Client Credentials vs. JWT Bearer).
7. It invokes the downstream `target_url` using an HTTP client equipped with native GCP SDK exponential backoff to handle transient network instability.
8. The resulting downstream OAuth token is returned to the caller.

### 5. Resiliency & Maintenance

* **Rate Limiting:** In-flight concurrent requests for the same token are bundled to prevent cache stampedes against the downstream IdP.
* **Failover Backoff:** If Google Secret Manager API calls fail or timeout, the proxy utilizes native GCP SDK (GAX) exponential backoff and retries to seamlessly handle transient upstream instability.
* **Audit Logging:** All transactions are logged using GCP structured logging, including the `traceId` to allow for end-to-end distributed tracing of failed token exchanges.
