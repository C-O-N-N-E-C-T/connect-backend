import { z } from 'zod';

/**
 * OSP-62: İş uçları için STUB Zod şemaları.
 * Bunlar yalnızca RBAC matrisini çalıştırabilmek için gereken en küçük gövde biçimleridir;
 * gerçek alanlar E8 (offline senkronizasyon) / E9 (koordinatör paneli) görevlerinde
 * tanımlanacaktır. `.strict()` bilinmeyen alanları reddeder ki istemci, sunucunun
 * görmezden geldiği alanlara güvenmesin.
 */

/** Serbest biçimli JSON nesnesi (stub tablolardaki `payload jsonb` sütununa karşılık gelir). */
const jsonObject = z.record(z.string(), z.unknown());

/** `:id` route parametresi: stub tabloların birincil anahtarı UUID'dir. */
export const victimIdParamSchema = z.string().uuid();

/** STUB — POST /api/v1/sync: kurtarıcının tek bir gözlem kaydı. */
export const syncBodySchema = z
  .object({
    payload: jsonObject,
  })
  .strict();

/** STUB — PATCH /api/v1/victims/:id/override: koordinatörün kayda uyguladığı alan değişiklikleri. */
export const victimOverrideBodySchema = z
  .object({
    // Boş bir override anlamsızdır; en az bir alan istenir.
    payload: jsonObject.refine((value) => Object.keys(value).length > 0, {
      message: 'payload must contain at least one field',
    }),
    reason: z.string().trim().min(1).max(500).optional(),
  })
  .strict();

/** STUB — POST /api/v1/assignments: kurtarıcıyı bir kazazede kaydına atama (kalıcı tablo yok). */
export const assignmentBodySchema = z
  .object({
    victim_id: z.string().uuid(),
    rescuer_id: z.string().uuid(),
    note: z.string().trim().max(500).optional(),
  })
  .strict();

export type SyncBody = z.infer<typeof syncBodySchema>;
export type VictimOverrideBody = z.infer<typeof victimOverrideBodySchema>;
export type AssignmentBody = z.infer<typeof assignmentBodySchema>;
