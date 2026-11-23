-- =========================================================================================
-- OSP-65: Kazazede verisi yazımı + audit satırı TEK transaction'da (AC-28)
-- =========================================================================================
-- Önceden backend önce kaydı yazıyor, sonra ayrı bir istekle audit satırını ekliyordu.
-- Audit insert'ü başarısız olursa istemci 500 alıyor ama değişiklik audit'siz kalıyordu
-- (ve /sync tekrar denendiğinde aynı gözlem iki kez yazılabiliyordu).
--
-- Bu fonksiyonlar yazımı ve audit_logs INSERT'ünü aynı fonksiyonda yapar (OSP-60
-- bind_device_session ile aynı yaklaşım). Fonksiyon tek bir transaction içinde çalışır:
-- audit INSERT'ü hata verirse kayıt değişikliği de geri alınır.
--
--   - public.sync_observation_audited(...)  POST /api/v1/sync      -> OBSERVATION_SYNC
--   - public.override_victim_audited(...)   PATCH /victims/:id/override -> VICTIM_UPDATE
--   - EXECUTE yalnızca service_role (backend); anon / authenticated asla.
--
-- Override gerekçesi (serbest metin, kişisel/sağlık verisi içerebilir) audit satırına
-- YAZILMAZ: audit_logs değiştirilemez ve 30 günlük silmeye (OSP-67) dahil değildir.
-- Audit satırında yalnızca `has_reason` bulunur; metnin kendisi victim_records içindeki
-- `_override.reason` alanında kalır ve kayıtla birlikte silinir.
-- =========================================================================================

-- 1. POST /sync: gözlem + OBSERVATION_SYNC ------------------------------------------------
CREATE OR REPLACE FUNCTION public.sync_observation_audited(
  p_actor_user_id UUID,
  p_actor_role public.app_role,
  p_device_id UUID,
  p_payload JSONB
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
  v_row public.rescuer_observations;
BEGIN
  -- created_by her zaman doğrulanmış kimlikten (req.auth.user_id) gelir.
  INSERT INTO public.rescuer_observations (payload, created_by)
  VALUES (p_payload, p_actor_user_id)
  RETURNING * INTO v_row;

  INSERT INTO public.audit_logs (actor_user_id, actor_role, device_id, action_type, target_record_id)
  VALUES (p_actor_user_id, p_actor_role, p_device_id, 'OBSERVATION_SYNC', v_row.id);

  RETURN jsonb_build_object(
    'id', v_row.id,
    'created_at', v_row.created_at,
    'created_by', v_row.created_by,
    'payload', v_row.payload
  );
END;
$$;

-- 2. PATCH /victims/:id/override: birleştir + VICTIM_UPDATE -------------------------------
-- Kayıt yoksa NULL döner ve hiçbir şey yazılmaz (404, audit satırı yok).
-- FOR UPDATE: eşzamanlı iki override birbirinin değişikliğini ezemez.
CREATE OR REPLACE FUNCTION public.override_victim_audited(
  p_victim_id UUID,
  p_actor_user_id UUID,
  p_actor_role public.app_role,
  p_device_id UUID,
  p_payload JSONB,
  p_reason TEXT DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
  v_row public.victim_records;
BEGIN
  SELECT * INTO v_row
    FROM public.victim_records
   WHERE id = p_victim_id
     FOR UPDATE;

  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  -- Son override'ı kimin/ne zaman yaptığı kayıt içinde izlenebilsin; gerekçe yalnızca
  -- verildiyse yazılır (jsonb_strip_nulls boş 'reason' alanını kaldırır).
  UPDATE public.victim_records
     SET payload = v_row.payload
                   || p_payload
                   || jsonb_build_object(
                        '_override',
                        jsonb_strip_nulls(jsonb_build_object(
                          'by', p_actor_user_id,
                          'at', now(),
                          'reason', p_reason
                        ))
                      )
   WHERE id = p_victim_id
  RETURNING * INTO v_row;

  -- Gerekçe metni değil, yalnızca var olup olmadığı.
  INSERT INTO public.audit_logs (actor_user_id, actor_role, device_id, action_type, target_record_id, metadata)
  VALUES (
    p_actor_user_id,
    p_actor_role,
    p_device_id,
    'VICTIM_UPDATE',
    v_row.id,
    jsonb_build_object('override', true, 'has_reason', p_reason IS NOT NULL)
  );

  RETURN jsonb_build_object(
    'id', v_row.id,
    'created_at', v_row.created_at,
    'created_by', v_row.created_by,
    'payload', v_row.payload
  );
END;
$$;

-- 3. Yetkiler: yalnızca backend ------------------------------------------------------------
REVOKE ALL ON FUNCTION public.sync_observation_audited(UUID, public.app_role, UUID, JSONB) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.sync_observation_audited(UUID, public.app_role, UUID, JSONB) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sync_observation_audited(UUID, public.app_role, UUID, JSONB) TO service_role;

REVOKE ALL ON FUNCTION public.override_victim_audited(UUID, UUID, public.app_role, UUID, JSONB, TEXT) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.override_victim_audited(UUID, UUID, public.app_role, UUID, JSONB, TEXT) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION public.override_victim_audited(UUID, UUID, public.app_role, UUID, JSONB, TEXT) TO service_role;
