# opa-authz-proxy

Sits between Oathkeeper's `remote_json` authorizer and OPA. It forwards the decision request to OPA and
turns OPA's answer into what Oathkeeper accepts: HTTP 200 (allow) or 403 (deny), plus identity headers
read from the decision.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `OPA_UPSTREAM_URL` | `http://localhost:8181` | OPA base URL; the request path is appended as is. |
| `LISTEN_ADDR` | `:8080` | Listen address. |
| `OPA_TOKEN` | unset | Shared secret sent to OPA as `Authorization: Bearer <OPA_TOKEN>` on every request. At least 32 characters, or the proxy refuses to start. Never logged. |

The caller's own `Authorization` header never reaches OPA. With `OPA_TOKEN` set, the proxy's bearer token
replaces it; without it, the header is removed. The inbound `X-Tenant-Id` is moved into
`input.organization_id` and removed from the request too.

## Responses

- `{"result": true|false}` (`/v1/data/rbac/allow`): 200 or 403, no identity headers.
- `{"result": {"allow", "groups", "organizations", "roles", "permissions", "reason"}}`
  (`/v1/data/rbac/decision`): 200 or 403, and always `X-User-Groups`, `X-User-Organizations`,
  `X-User-Roles`, `X-User-Permissions` as JSON arrays (`[]` when empty), plus `X-Authz-Reason`. Deny is
  403 whatever the reason, since Oathkeeper rejects any other status.

## Letting the proxy ask for `/decision`

OPA must run with token authentication (`--authentication=token`) so that `input.identity` carries the
caller's bearer token. Give OPA the same secret as `OPA_DECISION_TOKEN` (an env var on the OPA
container, from the same Secret as the proxy's `OPA_TOKEN`), and add this rule to the `system.authz`
policy next to the existing ones:

```rego
allow if {
	input.method == "POST"
	input.path == ["v1", "data", "rbac", "decision"]
	t := opa.runtime().env.OPA_DECISION_TOKEN
	count(t) >= 32
	input.identity == t
}
```

It opens `POST /v1/data/rbac/decision` only, and only to a caller presenting that token. If
`OPA_DECISION_TOKEN` is unset or shorter than 32 characters, the rule refuses everyone. The rule is valid
`rego.v1` and passes `opa check --strict` on OPA 0.68 and 0.70.
