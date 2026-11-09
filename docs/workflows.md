# AD offboarding preview recipes

These two flows implement a decision preview in an Okta Workflows sandbox. Build the helper first. Both recipes use synthetic identities and produce only a decision and reason.

## Request contract

Accept a JSON request body with a Text field called `payload`. Its value is a serialized JSON event object with exactly four keys. All four event values are strings. The Text envelope lets the flow validate the event before Workflows converts values to typed card fields. The CLI `request` command prints this envelope.

| Key | Source | Validation |
| --- | --- | --- |
| `event_id` | Windows System / EventID | Positive decimal text of up to five digits. This recipe handles `4725`. |
| `source_host` | Windows System / Computer | Lowercase, dotted ASCII hostname with valid DNS label syntax. Compare against the configured approved sources. |
| `target_sid` | Windows EventData / TargetSid | Domain account SID syntax, with four decimal components after `S-1-5-21`. Use the target SID, which identifies the disabled account. |
| `record_id` | Windows System / EventRecordID | Positive decimal text of up to 20 digits. Kept as text to preserve its original digits. |

The CLI can generate the inner event object from one Security audit event XML file with `normalize`. Serialize that object into the Text `payload` field to send it. The event ID, hostname, and SID in a payload are assertions supplied by the sender. The trusted inventory decides which identity is in scope. Microsoft documents that this event can also represent disabled computer accounts. Keep the inventory restricted to approved human user accounts. A record ID is local to its event log and is unsuitable as a global deduplication key.

## Sandbox setup

1. Create a table named `Lab Approved Sources` with a Text column `source_host`. Add the `approved_sources` entries from [inventory.json](../examples/inventory.json).
2. Create a table named `Lab Identity Inventory` with Text columns `target_sid`, `okta_user_id`, and `status`, and a True/False column `protected`. Add the five synthetic `identities` rows from that file. Require a unique SID and Okta ID for each mapping. Review the table before each test run.
3. Restrict table and flow edits to sandbox maintainers. In the synthetic test, `status` comes from the table.

## Flow 1. Resolve identity preview

Start with a [Helper Flow](https://help.okta.com/wf/en-us/Content/Topics/Workflows/learn/about-helper-flows.htm) card and Text input `target_sid`. Return two Text fields called `decision` and `reason`.

1. Use [Tables → Search Rows](https://help.okta.com/wf/en-us/Content/Topics/Workflows/function-reference/tables/stash_searchrows2.htm) for exact `target_sid` equality. Select the list result type with a limit of two so you can detect duplicates. Return the `protected` and `status` columns.
2. Use List → Length on the results. For zero rows, return `manual_review` / `unmapped_identity`. For more than one row or a row missing its protection setting, return `manual_review` / `invalid_inventory`. Read the row only when there is exactly one result.
3. If `protected` is true, return `manual_review` / `protected_identity`.
4. Use the remaining status branches in the decision table below. Return only `decision` and `reason` to the caller. Stop with a flow error on a table lookup failure. The empty-result branch applies to a successful search with zero rows.

For a separate sandbox test with actual test users, you can replace the table status with the [Okta → Read User](https://help.okta.com/wf/en-us/Content/Topics/Workflows/connector-reference/okta/actions/readuser.htm) status. Use the mapped `okta_user_id` from the table, verify the returned ID, and run the protection check before the read. Give the connection only the permissions required for the sandbox read and restrict access to the test population wherever your admin-role setup allows. Route read failures to the flow's error path. Create a separate casebook for these real sandbox statuses.

## Flow 2. Preview API endpoint

1. Start with [API Endpoint](https://help.okta.com/wf/en-us/Content/Topics/Workflows/function-reference/http/http_accept.htm). Set up the dedicated sandbox flow with [client-token authentication](https://help.okta.com/wf/en-us/Content/Topics/Workflows/execute/flow-api-endpoint-token.htm). Call it via POST with `Content-Type: application/json`, supplying the token in the `x-api-client-token` header. Copy the invoke URL from the console and remove the `clientToken` query parameter when using the header. Keep the token in your secret store.
2. Add `payload` under the API Endpoint card's **body** output group as Text. Pass it to [JSON → Parse](https://help.okta.com/wf/en-us/Content/Topics/Workflows/function-reference/JSON/json_parse.htm), configured to output an Object. Handle missing payloads and parse failures as `invalid` / `malformed_event`. Use [Object → Keys](https://help.okta.com/wf/en-us/Content/Topics/Workflows/function-reference/object/object_keys.htm) and List → Length to require four distinct keys.
3. Stringify the parsed event object, then use [Text → Find Pattern](https://help.okta.com/wf/en-us/Content/Topics/Workflows/function-reference/Text/text_match.htm) with the single-line pattern below. Require position `0`. Together with the key count, this matches all four allowed fields in any order and rejects numbers, nulls, or nested values. Then use Object → Get Multiple with Text outputs for the keys you need. Route any validation failure to `invalid` / `malformed_event`. JSON parsers may collapse duplicate keys. Validate duplicate keys at the sender or ingress boundary when you need to accept untrusted JSON.
4. Check for event ID `4725`, then query `Lab Approved Sources` by exact hostname. An unsupported event or an unapproved source returns the matching decision below. Treat a table lookup failure as a flow error.
5. Use Flow Control → Call Flow to invoke the identity helper with `target_sid`. Structure the branches so early outcomes bypass the helper. Return the two Text fields as a JSON object via a single top-level Return card. Use HTTP 200 for all handled decisions. Keep platform and connector errors separate from handled outcomes. When using nested If/Else or If Error cards, pass decision fields out of the branch and place the final Return outside the block.

Copy this validation pattern into the Find Pattern card in step 3.

```regex
^\{(?:"event_id":"[1-9][0-9]{0,4}"|"source_host":"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"|"target_sid":"S-1-5-21(?:-(?:0|[1-9][0-9]{0,9})){4}"|"record_id":"[1-9][0-9]{0,19}")(?:,(?:"event_id":"[1-9][0-9]{0,4}"|"source_host":"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"|"target_sid":"S-1-5-21(?:-(?:0|[1-9][0-9]{0,9})){4}"|"record_id":"[1-9][0-9]{0,19}")){3}\}(?![\s\S])
```

### Decision order

Evaluate from top to bottom. The first matching row wins.

| Condition | Decision | Reason |
| --- | --- | --- |
| Body fails validation | `invalid` | `malformed_event` |
| Valid event ID differs from 4725 | `ignored` | `unsupported_event` |
| Source absent from approved list | `ignored` | `unapproved_source` |
| SID has no inventory entry | `manual_review` | `unmapped_identity` |
| Duplicate SID or missing protection setting in the table | `manual_review` | `invalid_inventory` |
| Identity is protected | `manual_review` | `protected_identity` |
| Okta status is ACTIVE | `would_suspend` | `active_identity` |
| Okta status is SUSPENDED or DEPROVISIONED | `already_inactive` | `inactive_identity` |
| Any other status | `manual_review` | `other_status` |

The offline replay rejects an invalid inventory when loading it. The Workflows helper handles an ambiguous table lookup by routing it to manual review.

## Validate in the sandbox

1. Use `workflow_lab.py request` to print each request in [cases.json](../examples/cases.json). POST it to the sandbox preview endpoint from your approved API client. Save the HTTP response body to a local JSON file, then run `workflow_lab.py check` for that case. Check the HTTP status separately.
2. Temporarily add a duplicate SID row and confirm the helper returns `manual_review` / `invalid_inventory`. Remove the duplicate and rerun the active case.
3. Send a request with no token and confirm the platform rejects it. Repeat with a malformed inner event, such as `{"payload":"{"}`, and a valid token and confirm the flow returns `invalid` / `malformed_event`.
4. Check execution history and confirm that no write action ran and that the response exposes no identifiers. Keep any saved data synthetic.

## Boundary for an enforcement design

A production offboarding flow needs a trusted collector, authenticated ingress, freshness and replay controls, and a fresh source-of-truth check before acting. Revalidate that the identity still maps to the same account and that it is still disabled, including after retries or re-enablement. Apply protected-account rules, audit outcomes and partial failures, and define recovery before adding lifecycle actions. Okta account state, Okta sessions and tokens, downstream app provisioning, and app-owned sessions are distinct controls.

See the vendor references for [Windows Security Event 4725](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4725), [Okta Workflows connector scopes](https://help.okta.com/wf/en-us/Content/Topics/Workflows/connector-reference/okta/overviews/scopes.htm), [Okta user session operations](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserSessions/).
