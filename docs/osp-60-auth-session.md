# OSP-60: `POST /api/v1/auth/session` and `POST /api/v1/auth/logout`

[English](#english) · [Türkçe](#türkçe)

---

## English

**For:** client developers (Android OSP-74, Web OSP-69) and backend reviewers.
This is the contract as implemented. It matches
`connect-mobile/docs/osp-60-contract-assumptions.md` (A1–A5). The only difference is that logout
answers `204`, which the app accepts because it treats any 2xx as success.

### `POST /api/v1/auth/session`

Call it right after a successful Supabase sign-in.

```http
POST /api/v1/auth/session
Authorization: Bearer <supabase access_token>
Content-Type: application/json

{"device_id":"<uuid>","device_name":"Samsung SM-A546B"}
```

- `device_id`: a UUID. `device_name`: 1–100 characters after trimming. Unknown keys are ignored.
- `user_id` and `session_id` always come from the verified token, never from the body.

**200 for a rescuer** (`Cache-Control: no-store`):

```json
{
  "user_id": "…", "role": "rescuer", "device_id": "…",
  "offline_mission_grant": {
    "user_id": "…", "device_id": "…",
    "authenticated_at": "2026-11-22T10:00:00.000Z",
    "expires_at": "2026-11-25T10:00:00.000Z"
  }
}
```

**200 for a coordinator or administrator:** `{ "user_id", "role", "device_id" }`, with no grant.

The grant is **unsigned**. `expires_at` is exactly `authenticated_at + 72 h`.
`authenticated_at` is the moment the binding was written, which is also `user_devices.last_login_at`.

**Checks, in this order:**

| # | Check | Error | Audited |
|---|---|---|---|
| 0 | Malformed JSON body (checked by `jsonBody`, before the handler) | 400 `VALIDATION_ERROR` | no |
| 1 | Bearer token present and verified by `getClaims` | 401 `UNAUTHENTICATED` (+ `WWW-Authenticate: Bearer`) | no |
| 1b | Supabase Auth unreachable | 500 `INTERNAL_ERROR` | no |
| 2 | Body passes the Zod schema | 400 `VALIDATION_ERROR` | no |
| 3 | Profile exists, `is_active`, token not older than `all_sessions_revoked_at` | 403 `ACCOUNT_DISABLED` | `LOGIN_REJECTED` |
| 4 | `(user_id, device_id)` row is not revoked | 403 `DEVICE_REVOKED` | `LOGIN_REJECTED` |
| 5 | Bind and write the LOGIN audit row (one DB transaction) | 500 `INTERNAL_ERROR` on DB error | `LOGIN` |

The `/api/v1/auth/*` rate limit is 10 requests per minute per IP and answers 429 `RATE_LIMITED`.

**Binding rules** (implemented by `public.bind_device_session`):

- The row is upserted on `(user_id, device_id)`. A re-login replaces `session_id`, so tokens of
  the old session then get `SESSION_NOT_BOUND`.
- The revocation columns are never written. A revoked device stays revoked.
- A `session_id` is bound to at most one row. It is cleared from any other row first, and an
  optional partial unique index backs this up.

### `POST /api/v1/auth/logout`

```http
POST /api/v1/auth/logout
Authorization: Bearer <supabase access_token>
```

- Behind the OSP-61 guard. It clears `session_id` on the row with this `user_id` and
  `session_id`, writes `LOGOUT`, and answers **204**. The device row is kept.
- Call it **before** Supabase `signOut()`. Afterwards the same token gets `SESSION_NOT_BOUND`.
- An expired or revoked token is rejected by the guard (401 / 403) before the handler runs.
  In that case no LOGOUT row is written. The AC "100% audit" is read as "100% of authenticated
  calls" (team decision, see the PR).

### Database objects

Migration `20261122100000_osp60_session_binding.sql`:
`bind_device_session`, `unbind_device_session` and `record_login_rejected`.
They run as SECURITY INVOKER and only `service_role` may execute them.
Migration `20261122100100_osp60_session_id_unique.sql` is optional: a unique index on
`user_devices(session_id) WHERE session_id IS NOT NULL`.

---

## Türkçe

**Kime:** istemci geliştiricileri (Android OSP-74, Web OSP-69) ve backend reviewer'ları.
Bu belge yazılan sözleşmeyi anlatır ve `connect-mobile/docs/osp-60-contract-assumptions.md`
(A1–A5) ile uyumludur. Tek fark logout'un `204` dönmesidir; uygulama her 2xx yanıtı başarı
saydığı için bu uyumludur.

### `POST /api/v1/auth/session`

Supabase girişi başarılı olur olmaz çağrılır. Gövde `{device_id, device_name}` biçimindedir.

- `device_id` bir UUID'dir. `device_name`, baştaki ve sondaki boşluklar atıldıktan sonra 1–100 karakterdir.
- `user_id` ve `session_id` her zaman doğrulanmış token'dan alınır, gövdeden asla alınmaz.

**Kurtarıcı (rescuer)** için yanıt 200'dür ve 72 saatlik imzasız `offline_mission_grant` içerir.
**Koordinatör ve yönetici** için yanıt 200'dür, ama grant içermez.

**Kontrol sırası:**

0. Bozuk JSON gövde → 400 (`jsonBody` handler'dan önce yakalar).
1. Token → 401.
2. Gövde → 400.
3. Hesap → 403 `ACCOUNT_DISABLED`, audit'e `LOGIN_REJECTED` yazılır.
4. Cihaz iptali → 403 `DEVICE_REVOKED`, audit'e `LOGIN_REJECTED` yazılır.
5. Bağlama ve `LOGIN` audit kaydı tek transaction'da yapılır.

401 ve 400 durumları audit'e yazılmaz. Böylece kimliği doğrulanmamış biri tabloyu dolduramaz.

**Bağlama kuralları:**

- Satır `(user_id, device_id)` üzerinden oluşturulur ya da güncellenir.
- Yeniden girişte `session_id` güncellenir ve eski token `SESSION_NOT_BOUND` alır.
- İptal kolonlarına hiç yazılmaz, yani iptal edilmiş bir cihaz iptal edilmiş olarak kalır.
- Bir `session_id` en fazla bir satıra bağlanır.

### `POST /api/v1/auth/logout`

- Guard'ın arkasındadır. Bu oturumun bağını çözer, `LOGOUT` yazar ve **204** döner. Cihaz satırı silinmez.
- Supabase `signOut()` çağrısından **önce** çağrılmalıdır.
- Süresi dolmuş ya da iptal edilmiş token'ı guard reddeder ve LOGOUT kaydı yazılmaz. Kabul
  kriterindeki "%100 audit", "kimliği doğrulanmış çağrıların %100'ü" olarak okunur (ekip kararı, PR'a bakın).
