-- =============================================================================
-- OlysTech – Schema de referência
-- O backend usa arquivos JSON (data/*.json) em vez de SQL.
-- Este arquivo documenta a estrutura de cada "tabela" (coleção).
-- =============================================================================

-- ── Usuários ──────────────────────────────────────────────────────────────────
-- Arquivo: data/users.json
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  name          VARCHAR(255)  NOT NULL,
  email         VARCHAR(255)  UNIQUE NOT NULL,
  password_hash VARCHAR(64)   NOT NULL,          -- SHA-256 hex
  phone         VARCHAR(20),
  avatar_url    TEXT,
  active        BOOLEAN       DEFAULT TRUE,
  created_at    TIMESTAMPTZ   DEFAULT NOW(),
  updated_at    TIMESTAMPTZ
);

-- ── Sessões de login ──────────────────────────────────────────────────────────
-- Arquivo: data/sessions.json
CREATE TABLE IF NOT EXISTS sessions (
  id         SERIAL PRIMARY KEY,
  user_id    INT          NOT NULL REFERENCES users(id),
  email      VARCHAR(255) NOT NULL,
  ip         VARCHAR(50),
  created_at TIMESTAMPTZ  DEFAULT NOW()
);

-- ── Tokens de redefinição de senha ───────────────────────────────────────────
-- Arquivo: data/reset_tokens.json
CREATE TABLE IF NOT EXISTS reset_tokens (
  id         SERIAL PRIMARY KEY,
  email      VARCHAR(255) NOT NULL,
  code       CHAR(6)      NOT NULL,
  expires_at TIMESTAMPTZ  NOT NULL,
  created_at TIMESTAMPTZ  DEFAULT NOW()
);

-- ── Favoritos ─────────────────────────────────────────────────────────────────
-- Arquivo: data/favorites.json
CREATE TABLE IF NOT EXISTS favorites (
  id           SERIAL PRIMARY KEY,
  email        VARCHAR(255) NOT NULL,
  product_id   VARCHAR(50)  NOT NULL,
  product_name TEXT,
  price        NUMERIC(12,2),
  created_at   TIMESTAMPTZ  DEFAULT NOW(),
  UNIQUE (email, product_id)
);

-- ── Alertas de preço ──────────────────────────────────────────────────────────
-- Arquivo: data/price_alerts.json
CREATE TABLE IF NOT EXISTS price_alerts (
  id            SERIAL PRIMARY KEY,
  email         VARCHAR(255)  NOT NULL,
  product_id    VARCHAR(50)   NOT NULL,
  product_name  TEXT,
  current_price NUMERIC(12,2),
  target_price  NUMERIC(12,2) NOT NULL,
  active        BOOLEAN       DEFAULT TRUE,
  triggered_at  TIMESTAMPTZ,
  created_at    TIMESTAMPTZ   DEFAULT NOW(),
  updated_at    TIMESTAMPTZ
);

-- ── Pedidos ───────────────────────────────────────────────────────────────────
-- Arquivo: data/orders.json
CREATE TABLE IF NOT EXISTS orders (
  id             SERIAL PRIMARY KEY,
  email          VARCHAR(255)  NOT NULL,
  total          NUMERIC(12,2) NOT NULL,
  status         VARCHAR(30)   DEFAULT 'pending',
  -- status: pending | confirmed | shipped | delivered | cancelled
  payment_method VARCHAR(30)   DEFAULT 'credit_card',
  address_id     INT,
  created_at     TIMESTAMPTZ   DEFAULT NOW(),
  updated_at     TIMESTAMPTZ
);

-- ── Itens do pedido ───────────────────────────────────────────────────────────
-- Arquivo: data/order_items.json
CREATE TABLE IF NOT EXISTS order_items (
  id           SERIAL PRIMARY KEY,
  order_id     INT           NOT NULL REFERENCES orders(id),
  product_id   VARCHAR(50)   NOT NULL,
  product_name TEXT          NOT NULL,
  store        VARCHAR(100),
  price        NUMERIC(12,2) NOT NULL,
  quantity     INT           NOT NULL DEFAULT 1,
  created_at   TIMESTAMPTZ   DEFAULT NOW()
);

-- ── Endereços de entrega ──────────────────────────────────────────────────────
-- Arquivo: data/addresses.json
CREATE TABLE IF NOT EXISTS addresses (
  id           SERIAL PRIMARY KEY,
  email        VARCHAR(255) NOT NULL,
  label        VARCHAR(50)  DEFAULT 'Casa',   -- Casa, Trabalho, etc.
  recipient    VARCHAR(255),
  street       VARCHAR(255) NOT NULL,
  number       VARCHAR(20)  NOT NULL,
  complement   VARCHAR(100),
  neighborhood VARCHAR(100),
  city         VARCHAR(100) NOT NULL,
  state        CHAR(2)      NOT NULL,
  zip_code     VARCHAR(10)  NOT NULL,
  is_default   BOOLEAN      DEFAULT FALSE,
  created_at   TIMESTAMPTZ  DEFAULT NOW(),
  updated_at   TIMESTAMPTZ
);

-- ── Avaliações de produtos ────────────────────────────────────────────────────
-- Arquivo: data/reviews.json
CREATE TABLE IF NOT EXISTS reviews (
  id         SERIAL PRIMARY KEY,
  email      VARCHAR(255) NOT NULL,
  product_id VARCHAR(50)  NOT NULL,
  rating     SMALLINT     NOT NULL CHECK (rating BETWEEN 1 AND 5),
  comment    TEXT         DEFAULT '',
  created_at TIMESTAMPTZ  DEFAULT NOW(),
  UNIQUE (email, product_id)
);

-- ── Notificações ──────────────────────────────────────────────────────────────
-- Arquivo: data/notifications.json
-- tipos: welcome | order | price_alert | promo | system
CREATE TABLE IF NOT EXISTS notifications (
  id         SERIAL PRIMARY KEY,
  email      VARCHAR(255) NOT NULL,
  type       VARCHAR(30)  DEFAULT 'system',
  title      VARCHAR(255) NOT NULL,
  body       TEXT         NOT NULL,
  read       BOOLEAN      DEFAULT FALSE,
  created_at TIMESTAMPTZ  DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);
