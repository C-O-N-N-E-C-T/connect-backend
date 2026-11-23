# OSP-65: Immutable audit log / Değiştirilemez denetim günlüğü

FR-B-06 · NFR-SEC-06 · AC-28

## 1. Database protection (migration `20261122120000_osp65_audit_log_immutability.sql`)

| Rule | How |
|---|---|
| No UPDATE / DELETE, even with `service_role` | `BEFORE UPDATE OR DELETE ... FOR EACH ROW` trigger raises an exception |
| No TRUNCATE | `BEFORE TRUNCATE ... FOR EACH STATEMENT` trigger + privilege revoked |
| Clients (`anon`, `authenticated`) cannot write audit rows | `REVOKE ALL` first; then only `authenticated` gets `SELECT`, which stays under RLS (OSP-63). `anon` gets nothing |
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

**Writes need more than fail closed.** If a handler first changes a record and then calls `write()`, a failed audit insert gives the client a 500, but the change is already in the database without an audit row. So an endpoint that **changes data** must write the change and its audit row in **one DB transaction** (a SQL function, as OSP-60 `bind_device_session` does). Use `write()` directly only for read endpoints and for actions that change nothing.

## 3. Victim endpoints (`src/routes/business.ts`, OSP-62)

| Endpoint | Role | Who writes the audit row | Row |
|---|---|---|---|
| `GET /victims` | coordinator, administrator | route: `audit.list(req, { result_count })` | **one** `VICTIM_LIST_VIEW`, `metadata = { filters, result_count }` |
| `GET /victims/:id` | coordinator, administrator | route: `audit.view(req, id)` | `VICTIM_VIEW` + `target_record_id` |
| `PATCH /victims/:id/override` | coordinator | store, same transaction: `override_victim_audited` | `VICTIM_UPDATE` + `target_record_id`, `metadata = { override: true, has_reason }` |
| `POST /sync` | rescuer | store, same transaction: `sync_observation_audited` | `OBSERVATION_SYNC` + `target_record_id` (observation id) |
| `POST /assignments` | coordinator | not audited (see below) | none |

Failed requests (400, 401, 403, 404, ...) write no row. Only validated filter values go into `filters`.

### Reads

The route reads, then `await`s `audit.list` / `audit.view`, then answers. If the audit row cannot be written, the client gets 500 and no victim data. Nothing was changed, so nothing needs to be rolled back.

### Writes: one transaction (migration `20261123120000_osp65_atomic_victim_writes.sql`)

`VictimStore.insertObservation(payload, actor)` and `VictimStore.overrideVictim(id, payload, actor, { reason })` (`src/services/victim-store.ts`) call SQL functions that do the write **and** the `audit_logs` insert together:

- If the audit insert fails, the write is rolled back too, and the client gets 500. A retried `/sync` therefore cannot create a duplicate observation.
- `override_victim_audited` locks the row (`FOR UPDATE`), so two overrides at the same moment cannot overwrite each other. It returns `NULL` (-> 404, no row) for an unknown id.
- Both functions are `SECURITY INVOKER` with `search_path = ''`, and only `service_role` can execute them.
- The actor (`user_id`, `role`, `device_id`) comes from `req.auth`, never from the body.

After the store returns, the route calls `audit.recordedByStore(req)`, which only marks the request as audited for the enforcer.

**Override reason:** the coordinator's free-text reason may contain names or health data. `audit_logs` is append-only and is **not** purged after 30 days (OSP-67), so the text is **not** copied there. The audit row only has `has_reason: true | false`. The text itself is stored in the victim record as `payload._override.reason` and is deleted together with the record.

### `POST /assignments`

It is a stub right now: it validates the body but stores nothing (`persisted: false`), so it writes no audit row. When assignments are really stored, the endpoint must write its audit row in the same transaction (`TODO` in `src/routes/business.ts`). Whether "every authenticated action" (Jira) also covers actions that store nothing is a team decision.

### Audit enforcer (AC-28 safety net)

`requireVictimAudit` (`src/middleware/victim-audit-enforcer.ts`) is mounted on `/sync` and `/victims`. If a handler sends a **2xx** response for a request that was not marked as audited (by `audit.list` / `audit.view` / `audit.recordedByStore`), the body is dropped and the client gets `500 INTERNAL_ERROR`; the server logs `blocked unaudited METHOD path`. 3xx/4xx/5xx pass through. The enforcer protects the **response** only. The write paths above are what protect the **data**.

### Rules for new victim endpoints

1. Read endpoint: `await audit.<method>(req, ...)` before responding.
2. Write endpoint: do the change and the audit insert in one SQL function, then call `audit.recordedByStore(req)`.
3. Never put free text or victim data into audit `metadata`.
4. **Do not remove** the audit calls or `requireVictimAudit`.

## 4. Admin actions (for OSP-66)

Action types: `USER_CREATED`, `DEVICE_REVOKED`, `ACCOUNT_DISABLED`, `USER_REACTIVATED`. These actions change data, so follow the write rule in section 2: do the change and the `audit_logs` insert in one SQL function. Do not change the data first and then call `defaultAuditLogStore.write(...)`.

## 5. Written elsewhere

`LOGIN`, `LOGOUT`, `LOGIN_REJECTED` → OSP-60 SQL functions. `OBSERVATION_SYNC`, `VICTIM_UPDATE` → OSP-65 SQL functions (section 3). `RETENTION_PURGE` → OSP-67 `purge_expired_records()`. All of them only INSERT, so they work with the triggers.

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
- Yetkiler önce `REVOKE ALL` ile kaldırılır. Sonra yalnızca `authenticated` rolüne `SELECT` (RLS'e bağlı, OSP-63) ve `service_role` rolüne `SELECT, INSERT` verilir. `anon` hiçbir şey yapamaz.
- **Okuma uçları** (`GET /victims`, `GET /victims/:id`): route audit satırını cevaptan önce yazar. Yazılamazsa **500** döner ve veri gönderilmez.
- **Yazma uçları** (`POST /sync`, `PATCH /victims/:id/override`): değişiklik ve audit satırı **tek transaction'da** yazılır (`sync_observation_audited`, `override_victim_audited`). Audit yazılamazsa değişiklik de geri alınır. Böylece audit'siz değişiklik kalmaz ve `/sync` tekrar denendiğinde çift kayıt oluşmaz.
- Override gerekçesi (serbest metin) audit tablosuna **yazılmaz**, sadece `has_reason` yazılır. Metin kazazede kaydında kalır ve 30 gün sonra kayıtla birlikte silinir.
- `POST /assignments` henüz hiçbir şey kaydetmediği için audit edilmez (TODO). Bu konuda ekip kararı gerekiyor.
- `requireVictimAudit`: audit edilmemiş bir isteğe dönen 2xx victim cevabı **500**'e çevrilir.
- Admin uçları (OSP-66) yalnızca hiçbir şey değiştirmeyen işlemler için `defaultAuditLogStore.write()` kullanır. Değişiklik yapan işlemler audit satırını aynı transaction'da yazmalıdır.
- Liste sorguları **tek** bir `VICTIM_LIST_VIEW` özet satırı yazar.
- `actor_user_id` FK'sı kaldırıldı; kullanıcı silinse de audit kaydı değişmeden kalır.
