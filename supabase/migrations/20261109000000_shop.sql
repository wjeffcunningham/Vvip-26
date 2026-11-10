-- VVIP Shoppe: stock + orders for on-site Stripe Checkout.
-- Paste into Supabase Dashboard → SQL Editor → Run. Safe to re-run.

-- ── STOCK ──────────────────────────────────────────────────────────────
-- One row per sellable unit. sku = "<item id>" or "<item id>:<variant>"
-- e.g. "tee-basic:M". Items/variants with NO row here are treated as
-- unlimited (not tracked). Set qty to 0 to mark sold out.
create table if not exists public.shop_stock (
  sku        text primary key,
  qty        integer not null default 0 check (qty >= 0),
  updated_at timestamptz not null default now()
);
alter table public.shop_stock enable row level security;
drop policy if exists "shop_stock public read" on public.shop_stock;
create policy "shop_stock public read" on public.shop_stock for select using (true);

-- ── ORDERS ─────────────────────────────────────────────────────────────
-- Written only by the edge functions (service role). No public policies.
create table if not exists public.shop_orders (
  id                uuid primary key,
  created_at        timestamptz not null default now(),
  status            text not null default 'pending',   -- pending | paid | expired | error
  items             jsonb not null,                    -- [{sku,id,variant,qty,title,unit_amount}]
  region            text,                              -- CA | US | INTL | PICKUP
  stripe_session_id text unique,
  email             text,
  name              text,
  phone             text,
  shipping          jsonb,                             -- Stripe address object
  amount_total      integer,                           -- cents
  currency          text,
  paid_at           timestamptz,
  shipped_at        timestamptz                        -- fill in by hand when it goes out
);
alter table public.shop_orders enable row level security;

-- ── FULFIL (called by shop-webhook) ────────────────────────────────────
-- Marks an order paid and decrements stock in one transaction.
-- Returns false if the order was already paid (Stripe retries are safe).
create or replace function public.shop_fulfil(
  p_order_id uuid, p_session text, p_email text, p_name text, p_phone text,
  p_shipping jsonb, p_amount integer, p_currency text
) returns boolean
language plpgsql security definer set search_path = public as $$
declare v_items jsonb; it jsonb;
begin
  update shop_orders
     set status = 'paid', paid_at = now(), stripe_session_id = p_session,
         email = p_email, name = p_name, phone = p_phone, shipping = p_shipping,
         amount_total = p_amount, currency = p_currency
   where id = p_order_id and status <> 'paid'
  returning items into v_items;
  if not found then return false; end if;
  for it in select * from jsonb_array_elements(v_items) loop
    update shop_stock
       set qty = greatest(qty - (it->>'qty')::int, 0), updated_at = now()
     where sku = it->>'sku';
  end loop;
  return true;
end $$;
revoke all on function public.shop_fulfil(uuid,text,text,text,text,jsonb,integer,text) from public, anon, authenticated;

-- ── EXAMPLE STOCK (edit numbers, then run) ─────────────────────────────
-- insert into public.shop_stock (sku, qty) values
--   ('tee-basic:S', 5), ('tee-basic:M', 10), ('tee-basic:L', 10), ('tee-basic:XL', 5), ('tee-basic:XXL', 2),
--   ('tee-vvip-plus:S', 2), ('tee-vvip-plus:M', 4), ('tee-vvip-plus:L', 4), ('tee-vvip-plus:XL', 2), ('tee-vvip-plus:XXL', 1),
--   ('tote-1', 20), ('sticker-pack', 50), ('sticker-book', 15)
-- on conflict (sku) do update set qty = excluded.qty, updated_at = now();
