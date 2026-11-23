-- =========================================================================================
-- OSP-65: Yalnızca eklenebilir (append-only) public.audit_logs (FR-B-06, NFR-SEC-06, AC-28)
-- =========================================================================================
-- service_role RLS'i atladığı için değiştirilemezlik hem yetkilerle HEM trigger'larla sağlanır:
--   1. actor_user_id FK'sı kaldırılır: ON DELETE SET NULL, kullanıcı silinince audit satırını
--      UPDATE ederdi (aşağıdaki trigger bunu engeller). Actor id zaten log'da kalmalıdır.
--   2. Hiç kimse audit_logs üzerinde UPDATE, DELETE veya TRUNCATE yapamaz. İstemciler (anon,
--      authenticated) INSERT de yapamaz; audit satırlarını yalnızca backend (service_role) ve
--      OSP-60 / OSP-67 SQL fonksiyonları yazar. İstemcilerin SELECT'i RLS'e bağlı kalır (OSP-63).
--   3. BEFORE UPDATE OR DELETE (satır) ve BEFORE TRUNCATE (statement) trigger'ları hata
--      fırlatır; service_role ve SECURITY DEFINER fonksiyonlar için de geçerlidir.
--
-- Bilinen sınır: superuser / tablo sahibi trigger'ları yine de kapatabilir
-- (ALTER TABLE ... DISABLE TRIGGER). Bu, uygulamanın dışında bir veritabanı yönetimi
-- işlemidir ve API anahtarlarıyla yapılamaz.
-- =========================================================================================

-- 1. actor_user_id -> auth.users foreign key'ini kaldır (adı ne olursa olsun) --------------
DO $$
DECLARE
  v_constraint TEXT;
BEGIN
  FOR v_constraint IN
    SELECT c.conname
    FROM pg_constraint c
    JOIN pg_attribute a
      ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
    WHERE c.conrelid = 'public.audit_logs'::regclass
      AND c.contype = 'f'
      AND a.attname = 'actor_user_id'
  LOOP
    EXECUTE format('ALTER TABLE public.audit_logs DROP CONSTRAINT %I', v_constraint);
  END LOOP;
END;
$$;

-- 2. Yetkiler -----------------------------------------------------------------------------
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.audit_logs FROM PUBLIC, anon, authenticated;
REVOKE UPDATE, DELETE, TRUNCATE ON public.audit_logs FROM service_role;
GRANT SELECT, INSERT ON public.audit_logs TO service_role;

-- 3. Trigger fonksiyonu -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.audit_logs_reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  RAISE EXCEPTION 'public.audit_logs is append-only: % is not allowed', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;

REVOKE ALL ON FUNCTION public.audit_logs_reject_mutation() FROM PUBLIC;

-- 4. Trigger'lar --------------------------------------------------------------------------
DROP TRIGGER IF EXISTS audit_logs_no_update_delete ON public.audit_logs;
CREATE TRIGGER audit_logs_no_update_delete
  BEFORE UPDATE OR DELETE ON public.audit_logs
  FOR EACH ROW
  EXECUTE FUNCTION public.audit_logs_reject_mutation();

DROP TRIGGER IF EXISTS audit_logs_no_truncate ON public.audit_logs;
CREATE TRIGGER audit_logs_no_truncate
  BEFORE TRUNCATE ON public.audit_logs
  FOR EACH STATEMENT
  EXECUTE FUNCTION public.audit_logs_reject_mutation();