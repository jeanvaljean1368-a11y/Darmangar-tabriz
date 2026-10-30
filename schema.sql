-- درمان‌گر: طرح اولیه پایگاه داده برای Cloudflare D1 / SQLite
-- پیش از استفاده واقعی، دسترسی‌ها و اعتبارسنجی سمت سرور الزامی است.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role IN ('requester','provider','admin')),
  phone TEXT UNIQUE,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  password_iterations INTEGER NOT NULL DEFAULT 310000,
  login_failed_attempts INTEGER NOT NULL DEFAULT 0,
  login_locked_until TEXT,
  display_name TEXT,
  avatar_url TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1))
);

CREATE TABLE IF NOT EXISTS provider_profiles (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  profession TEXT NOT NULL,
  bio TEXT,
  verification_status TEXT NOT NULL DEFAULT 'pending' CHECK (verification_status IN ('pending','approved','rejected','suspended')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS service_catalog (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1))
);

CREATE TABLE IF NOT EXISTS provider_services (
  provider_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  service_id TEXT NOT NULL REFERENCES service_catalog(id),
  approval_status TEXT NOT NULL DEFAULT 'pending' CHECK (approval_status IN ('pending','approved','rejected')),
  approved_by TEXT REFERENCES users(id),
  approved_at TEXT,
  PRIMARY KEY (provider_user_id, service_id)
);

CREATE TABLE IF NOT EXISTS provider_documents (
  id TEXT PRIMARY KEY,
  provider_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  document_type TEXT NOT NULL,
  object_key TEXT NOT NULL,
  review_status TEXT NOT NULL DEFAULT 'pending' CHECK (review_status IN ('pending','approved','rejected')),
  reviewed_by TEXT REFERENCES users(id),
  reviewed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS service_requests (
  id TEXT PRIMARY KEY,
  requester_user_id TEXT NOT NULL REFERENCES users(id),
  service_id TEXT NOT NULL REFERENCES service_catalog(id),
  description TEXT NOT NULL,
  city TEXT NOT NULL DEFAULT 'تبریز',
  address_text TEXT NOT NULL,
  desired_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','selected','in_progress','completed','cancelled','expired')),
  offer_count INTEGER NOT NULL DEFAULT 0 CHECK (offer_count BETWEEN 0 AND 5),
  rebroadcast_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS offers (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL REFERENCES service_requests(id) ON DELETE CASCADE,
  provider_user_id TEXT NOT NULL REFERENCES users(id),
  price_toman INTEGER NOT NULL CHECK (price_toman >= 0),
  can_arrive INTEGER NOT NULL CHECK (can_arrive IN (0,1)),
  arrival_at TEXT,
  note TEXT,
  status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted','accepted','declined','withdrawn')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(request_id, provider_user_id)
);

CREATE TABLE IF NOT EXISTS feedback (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id),
  category TEXT NOT NULL CHECK (category IN ('suggestion','complaint','bug','thanks')),
  message TEXT NOT NULL CHECK (length(message) BETWEEN 1 AND 1500),
  contact_phone TEXT,
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','reviewing','resolved','closed')),
  admin_note TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  handled_at TEXT,
  handled_by TEXT REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE REFERENCES service_requests(id),
  requester_user_id TEXT NOT NULL REFERENCES users(id),
  provider_user_id TEXT NOT NULL REFERENCES users(id),
  stars INTEGER NOT NULL CHECK (stars BETWEEN 1 AND 5),
  comment TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS admin_audit_log (
  id TEXT PRIMARY KEY,
  admin_user_id TEXT NOT NULL REFERENCES users(id),
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_requests_status_time ON service_requests(status, desired_at);
CREATE INDEX IF NOT EXISTS idx_offers_request ON offers(request_id, created_at);
CREATE INDEX IF NOT EXISTS idx_provider_services_approval ON provider_services(approval_status, service_id);
CREATE INDEX IF NOT EXISTS idx_feedback_status_time ON feedback(status, created_at);
CREATE INDEX IF NOT EXISTS idx_documents_provider_status ON provider_documents(provider_user_id, review_status);


-- نسخه ۱۰: قواعد پایه‌ای در خود پایگاه داده
-- حتی اگر برنامهٔ فرانت‌اند خطا کند، تعداد پیشنهادهای یک درخواست از ۵ بیشتر نمی‌شود.
CREATE TRIGGER IF NOT EXISTS offers_limit_before_insert
BEFORE INSERT ON offers
BEGIN
  SELECT CASE
    WHEN (SELECT status FROM service_requests WHERE id = NEW.request_id) IS NULL
      THEN RAISE(ABORT, 'request_not_found')
    WHEN (SELECT status FROM service_requests WHERE id = NEW.request_id) <> 'open'
      THEN RAISE(ABORT, 'request_not_open')
    WHEN (SELECT offer_count FROM service_requests WHERE id = NEW.request_id) >= 5
      THEN RAISE(ABORT, 'offer_limit_reached')
    WHEN (SELECT verification_status FROM provider_profiles WHERE user_id = NEW.provider_user_id) <> 'approved'
      THEN RAISE(ABORT, 'provider_not_approved')
    WHEN NOT EXISTS (
      SELECT 1 FROM provider_services ps
      WHERE ps.provider_user_id = NEW.provider_user_id
        AND ps.service_id = (SELECT service_id FROM service_requests WHERE id = NEW.request_id)
        AND ps.approval_status = 'approved'
    ) THEN RAISE(ABORT, 'provider_service_not_approved')
  END;
END;

CREATE TRIGGER IF NOT EXISTS offers_count_after_insert
AFTER INSERT ON offers
BEGIN
  UPDATE service_requests
  SET offer_count = offer_count + 1,
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
  WHERE id = NEW.request_id;
END;

CREATE TRIGGER IF NOT EXISTS offers_count_after_delete
AFTER DELETE ON offers
BEGIN
  UPDATE service_requests
  SET offer_count = (SELECT COUNT(*) FROM offers WHERE request_id = OLD.request_id),
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
  WHERE id = OLD.request_id;
END;

-- نسخه ۱۲: کدهای یک‌بارمصرف ورود؛ کد خام ذخیره نمی‌شود.
CREATE TABLE IF NOT EXISTS otp_challenges (
  id TEXT PRIMARY KEY,
  phone TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_otp_phone_created ON otp_challenges(phone, created_at);

-- نسخه ۱۴: داده‌های اولیهٔ فهرست خدمات (قابل اجرای مجدد)
INSERT OR IGNORE INTO service_catalog (id,name,description,is_active) VALUES
('home-nursing','پرستاری در منزل','انواع تزریقات، خدمات بخیه، پانسمان و درمان زخم و مراقبت از سالمند',1),
('physiotherapy','فیزیوتراپی','خدمات فیزیوتراپی توسط ارائه‌دهندهٔ تأییدشده',1),
('massage','ماساژدرمانی','خدمات ماساژ توسط ارائه‌دهندهٔ تأییدشده',1);


-- نسخه ۱۵: گفت‌وگوی خصوصی فقط پس از انتخاب پیشنهاد
CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE REFERENCES service_requests(id) ON DELETE CASCADE,
  requester_user_id TEXT NOT NULL REFERENCES users(id),
  provider_user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS chat_messages (
  id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  sender_user_id TEXT NOT NULL REFERENCES users(id),
  message_text TEXT NOT NULL CHECK (length(message_text) BETWEEN 1 AND 2000),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  read_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation_time
  ON chat_messages(conversation_id, created_at);
CREATE INDEX IF NOT EXISTS idx_conversations_requester
  ON conversations(requester_user_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_conversations_provider
  ON conversations(provider_user_id, updated_at);

-- Push subscriptions: endpoints and encryption keys are private user/device data.
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  user_agent TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  disabled_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id, disabled_at);


-- v17: رمز ثابت ورود (پس از تأیید اولیه شماره موبایل)
CREATE TABLE IF NOT EXISTS user_login_pins (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  pin_hash TEXT NOT NULL,
  pin_salt TEXT NOT NULL,
  iterations INTEGER NOT NULL DEFAULT 210000,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);


-- One-time enrollment invites for SMS-free initial account setup.
CREATE TABLE IF NOT EXISTS enrollment_invites (
  id TEXT PRIMARY KEY,
  phone TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('requester','provider')),
  code_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_enrollment_invites_phone ON enrollment_invites(phone, consumed_at, expires_at);
