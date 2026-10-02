# VASH repository and deployed site: security recheck

**Date:** 2 October 2026  
**Repository:** https://github.com/S-Abhiram05/Hack2ignite-VASH  
**Reviewed HEAD:** `9f191affb4cc66ad27451cf59cb4b1fc755180e2`  
**Deployment:** https://vash-virid.vercel.app/

## Scope and confidence

This is a source review of the current GitHub HEAD and a read-only browser check of the public Vercel site. The deployment's exact commit was not exposed, so source-to-live equivalence cannot be proved. No authenticated API calls, exploitation, active scanning, database inspection, or infrastructure configuration review was performed. Ratings describe plausible impact in the reviewed design, not confirmed compromise.

The Vercel configuration builds `frontend/dist` only. The page loads, and in-app navigation reaches the login gateway. Directly loading `/login` returned a Vercel `404: NOT_FOUND`, consistent with a missing SPA rewrite. The live homepage displays fixed figures including “₹4.2 Billion,” “142,” and “94.2%” as live telemetry; the corresponding source hard-codes them. These are product integrity issues, not proof that the backend is publicly deployed.

## Findings and missing controls

| Priority | Finding and evidence | Impact / required change |
| --- | --- | --- |
| **Critical** | `frontend/src/state/StoreContext.tsx` embeds `admin/adminpassword` and several bank IDs with `password123`; `LoginGateway.tsx` checks these client-side and continues after a failed/unreachable `http://localhost:8000/api/auth/login`. It sets `isAuthenticated` after client-generated OTP and client-read JSON. | Anyone receiving the frontend can inspect and imitate the UI gate. Remove bundled credentials and local authentication state as an authority; require a server-verified session on every protected API operation. Treat the current hosted workspace as a demo until that is done. |
| **High** | `main.py` issues a fully usable bearer token immediately after password login and logs `mfa_verified: False`. The OTP is generated with `Math.random()` in the browser and displayed as a hint; SDK identifier/owner/signature checks occur in browser code, with permissive identifier matching and an optional signature field. | MFA and SDK checks do not protect backend APIs. Implement server-side challenge enrollment, expiry, rate limiting and verification before issuing a privileged token; validate signed license material server-side or remove the claim. |
| **High** | `main.py` `/api/graph` filters the flagged starting node by `bank_id` but matches and returns all neighboring accounts and edge amounts, regardless of their bank. `/ingest_transaction` does not bind `payload.bank_id` to the authenticated institution; merged nodes are not assigned a bank in this write. | Cross-tenant graph disclosure and integrity problems are possible when shared graph data exists. Define permitted cross-bank disclosure, enforce it on every returned node/edge, bind ingest ownership to JWT institution, and test with two tenant fixtures. |
| **High** | `main.py` `/api/psi/intersect` accepts two client-provided lists and runs ordinary set intersection; `psi_engine.py` calls `hashlib.sha256` without importing `hashlib`. `PSIDashboard.tsx` uses a public, fixed salt. | The stated private set intersection is neither a verified PSI protocol nor reliable when `encrypt_set` is called. Fix the runtime error, stop calling this PSI, and design a reviewed privacy protocol with institution-controlled inputs, per-party secrets and leakage analysis. |
| **Medium** | `LoginGateway.tsx` uses `http://localhost:8000` from the deployed page; `vercel.json` only builds the frontend. Backend requests from visitors target their own machines and errors are ignored. | Deploy an HTTPS API, configure a production base URL, require successful authentication, and use a proxy/rewrite or same-origin API where suitable. |
| **Medium** | `main.py` tracks replay nonces in a process-local set and clears all at 10,000; it also creates graph edges before queuing the worker and uses a millisecond-derived transaction ID. | Replay protection and idempotence fail across processes, restarts or clear events; retries and the worker may duplicate edges. Use a durable unique transaction key, an atomic insert/constraint, and an idempotent queue worker. |
| **Medium** | `config.py` replaces absent JWT/HMAC secret and PSI salt with fresh random values per process. | This avoids a published default but separate API/worker processes may disagree and restarts revoke all sessions. Fail startup in non-demo environments unless stable, securely provisioned secrets are set; rotate deliberately. |
| **Medium** | `audit_logger.py` writes a hash chain to an ordinary local file. `StoreContext.tsx` dispatch functions only append local success messages. | Neither immutable audit retention nor actual regulatory dispatch is demonstrated. Use append-only central retention with tamper detection, a verifier, durable delivery status and evidence from the real destination. |
| **Low / product integrity** | The homepage presents static metrics and a node exposure checker whose logic is a string heuristic (`includes('7')` or `includes('x')`). The live site also 404s on a direct `/login` load. | Label demo numbers and checker as simulations, or connect them to measured data and authoritative checks. Add a SPA fallback rewrite and verify refreshes on routes. |

## Changes since the preceding review

The newer code removed a fixed fallback secret, restricted CORS to named origins/methods/headers, added timestamp normalization and a five-minute freshness check, and filters several account/statistics queries by institution. Those changes narrow some earlier risks. They do **not** make the browser login authoritative, enforce backend MFA, isolate all graph neighbors, or deploy the API on Vercel. The security log now explicitly records that a password login has not completed MFA, while still returning the token.

## Suggested order of work

1. Remove public demo credentials and make all protected data/actions depend on a backend-verified identity and tenant. Issue privileged tokens only after server MFA. Do not use client local storage or client role values for authorization.
2. Enforce tenant ownership on ingestion and every graph/read response, with explicit policy for cross-bank links and automated two-tenant tests.
3. Connect the hosted frontend to a real HTTPS API and fail closed on unavailable authentication. Add route rewrites.
4. Make transaction IDs and replay/idempotency durable, then implement audit retention and actual dispatch acknowledgments.
5. Replace PSI, PQC, HSM, live telemetry, exposure, and compliance claims with validated implementations or clearly mark their current demo status.

## Source pointers

- [Frontend login gateway](https://github.com/S-Abhiram05/Hack2ignite-VASH/blob/9f191affb4cc66ad27451cf59cb4b1fc755180e2/frontend/src/components/LoginGateway.tsx), [store and bundled accounts](https://github.com/S-Abhiram05/Hack2ignite-VASH/blob/9f191affb4cc66ad27451cf59cb4b1fc755180e2/frontend/src/state/StoreContext.tsx)
- [API authentication, graph, ingest and PSI route](https://github.com/S-Abhiram05/Hack2ignite-VASH/blob/9f191affb4cc66ad27451cf59cb4b1fc755180e2/main.py), [PSI engine](https://github.com/S-Abhiram05/Hack2ignite-VASH/blob/9f191affb4cc66ad27451cf59cb4b1fc755180e2/psi_engine.py), [configuration](https://github.com/S-Abhiram05/Hack2ignite-VASH/blob/9f191affb4cc66ad27451cf59cb4b1fc755180e2/config.py)
- [Vercel build configuration](https://github.com/S-Abhiram05/Hack2ignite-VASH/blob/9f191affb4cc66ad27451cf59cb4b1fc755180e2/vercel.json), [live site](https://vash-virid.vercel.app/)
