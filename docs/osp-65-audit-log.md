# OSP-65: Immutable audit log / Değiştirilemez denetim günlüğü

FR-B-06 · NFR-SEC-06 · AC-28

## 1. Database protection (migration `20261122120000_osp65_audit_log_immutability.sql`)

| Rule | How |
|---|---|
| No UPDATE / DELETE, even with `service_role` | `BEFORE UPDATE OR DELETE ... FOR EACH ROW` trigger raises an exception |
| No TRUNCATE | `BEFORE TRUNCATE ... FOR EACH STATEMENT` trigger + privilege revoked |
| Clients (`anon`, `authenticated`) cannot write audit rows | `INSERT/UPDATE/DELETE/TRUNCATE` revoked; SELECT stays under RLS (OSP-63) |
| `service_role` | `SELECT, INSERT` only |
| Deleting a user does not touch audit rows | `actor_user_id` foreign key removed (it was `ON DELETE SET NULL`, i.e. an UPDATE) |

**Known limit:** a superuser / the table owner can disable triggers. This is a DBA action, not reachable with the API keys.

## 2. Writing audit rows from the backend

```ts
import { defaultAuditLogStore } from '../services/audit-log.js';

await defaultAuditLogStore.write({
  actor: req.auth!,               // always from the OSP-61 guard
  action_type: 'DEVICE_REVOKED',  // one of AUDIT_ACTION_TYPES (src/types/database.ts)
  target_record_id: targetUserId, // optional
  metadata: { device_id },        // optional, JSONB
});
```

**Fail closed:** `write()` throws `500 INTERNAL_ERROR` if the row cannot be stored. Always `await` it **before** sending the response, so no data leaves without an audit row.

## 3. Victim endpoints (skeleton in OSP-65, filled in by OSP-62)

`src/routes/victims.ts` already contains the four routes with their audit calls:

| Endpoint | Audit call | Row |
|---|---|---|
| `GET /victims/:id` | `audit.view(req, id)` | `VICTIM_VIEW` + `target_record_id` |
| `POST /victims` | `audit.create(req, newId)` | `VICTIM_CREATE` + `target_record_id` |
| `PATCH /victims/:id` | `audit.update(req, id)` | `VICTIM_UPDATE` + `target_record_id` |
| `GET /victims` | `audit.list(req, { filters, result_count })` | **one** `VICTIM_LIST_VIEW`, `metadata = { filters, result_count }` |

Failed requests (400, 404, 401, ...) write no row. Only validated filter values go into `filters`.

Database access goes through `VictimRepository` (`src/services/victim-repository.ts`). Until OSP-62 provides the Supabase implementation, the default repository answers **501 NOT_IMPLEMENTED** (no data, no audit row).

### Audit enforcer (AC-28 safety net)

`requireVictimAudit` (`src/middleware/victim-audit-enforcer.ts`) is mounted on `/victims`. If a handler sends a **2xx** response without a successful `audit.*` call, the body is dropped and the client gets `500 INTERNAL_ERROR`; the server logs `blocked unaudited METHOD path`. 3xx/4xx/5xx pass through. So a victim endpoint that forgets its audit call cannot leak data, and its tests fail.

### TODO for OSP-62

1. Implement the Supabase `VictimRepository` (`public.victim_records`) and make it the default in `createVictimRouter`.
2. Replace the minimal Zod schemas (body, query) with the real ones.
3. Add RBAC checks (`TODO(OSP-62)` markers in `src/routes/victims.ts`).
4. **Do not remove** the `audit.*` calls or `requireVictimAudit`. A new victim endpoint must call the matching `audit.*` before responding.

## 4. Admin actions (for OSP-66)

Use `defaultAuditLogStore.write(...)` with: `USER_CREATED`, `DEVICE_REVOKED`, `ACCOUNT_DISABLED`, `USER_REACTIVATED`.

## 5. Written elsewhere

`LOGIN`, `LOGOUT`, `LOGIN_REJECTED` → OSP-60 SQL functions. `RETENTION_PURGE` → OSP-67 `purge_expired_records()`. All of them only INSERT, so they work with the triggers.

## 6. Manual check on local Supabase

```sql
-- supabase db reset, then in Studio SQL editor / psql:
INSERT INTO public.audit_logs (action_type) VALUES ('OSP65_CHECK');   -- OK
UPDATE public.audit_logs SET action_type = 'X';                       -- ERROR: append-only
DELETE FROM public.audit_logs;                                        -- ERROR: append-only
TRUNCATE public.audit_logs;                                           -- ERROR: append-only
SELECT public.purge_expired_records();                                -- OK
```

---

## Özet (TR)

- `audit_logs` artık **yalnızca eklenebilir**: UPDATE, DELETE ve TRUNCATE `service_role` ile bile DB hatası verir.
- Backend audit satırlarını sadece `AuditLogStore.write()` ile yazar; yazılamazsa istek **500** döner (fail-closed).
- Victim uçlarının iskeleti (`src/routes/victims.ts`) audit çağrılarıyla birlikte hazır; OSP-62 yalnızca repository, doğrulama ve RBAC'ı doldurur. Doldurulana kadar uçlar **501** döner.
- `requireVictimAudit`: audit yazılmadan dönen her 2xx victim cevabı **500**'e çevrilir, veri sızmaz.
- Admin uçları (OSP-66) `defaultAuditLogStore.write()` kullanır.
- Liste sorguları **tek** bir `VICTIM_LIST_VIEW` özet satırı yazar.
- `actor_user_id` FK'sı kaldırıldı; kullanıcı silinse de audit kaydı değişmeden kalır.