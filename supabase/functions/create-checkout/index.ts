// create-checkout — VVIP Shoppe cart → Stripe Checkout Session.
// Deploy: Supabase Dashboard → Edge Functions → Deploy new function → name "create-checkout" → paste.
// Secrets needed: STRIPE_SECRET_KEY (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are built in).
// Prices are read from the live shoppe.json, never from the browser.

import { createClient } from 'npm:@supabase/supabase-js@2';

const SITE = 'https://vvipmedia.net';
const SHOPPE_JSON = SITE + '/shoppe/shoppe.json';
const IMG_BASE = SITE + '/shoppe/';
const MAX_QTY = 10;

// Flat shipping per order, in CENTS CAD. ── EDIT THESE ──
const INTL_COUNTRIES = ['GB','IE','FR','DE','NL','BE','LU','ES','PT','IT','AT','CH','SE','NO','DK','FI','IS','PL','CZ','AU','NZ','JP','KR','MX'];
const SHIPPING: Record<string, { countries: string[] | null; name: string; amount: number }> = {
  CA:     { countries: ['CA'],         name: 'Canada (tracked)',          amount: 1500 },
  US:     { countries: ['US'],         name: 'USA (tracked)',             amount: 2000 },
  INTL:   { countries: INTL_COUNTRIES, name: 'International (tracked)',   amount: 3000 },
  PICKUP: { countries: null,           name: 'Local pickup (Vancouver)',  amount: 0 },
};

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });

// Stripe wants form-encoded nested params: line_items[0][price_data][currency]=cad
function form(obj: Record<string, unknown>, prefix = '', out = new URLSearchParams()) {
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    const key = prefix ? `${prefix}[${k}]` : k;
    if (typeof v === 'object') form(v as Record<string, unknown>, key, out);
    else out.append(key, String(v));
  }
  return out;
}

type Line = { sku: string; id: string; variant: string | null; qty: number; product: any };
const labelOf = (l: Line) => l.variant ? `${l.product.title} (${l.variant})` : l.product.title;

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  if (req.method !== 'POST') return json({ error: 'POST only' }, 405);

  try {
    const { items, region } = await req.json();
    const ship = SHIPPING[region];
    if (!ship) return json({ error: 'Pick where to ship.' }, 400);
    if (!Array.isArray(items) || !items.length || items.length > 20) return json({ error: 'Cart is empty.' }, 400);

    const cat = await (await fetch(SHOPPE_JSON + '?t=' + Date.now())).json();
    const byId = new Map<string, any>((Array.isArray(cat) ? cat : cat.items || []).filter((p: any) => p.id).map((p: any) => [p.id, p]));

    // Validate + merge duplicate lines
    const merged = new Map<string, Line>();
    for (const it of items) {
      const p = byId.get(String(it?.id || ''));
      if (!p || !p.checkout || !p.available) return json({ error: `"${p?.title || it?.id}" isn't available right now.` }, 400);
      if (String(p.currency || 'CAD').toUpperCase() !== 'CAD') return json({ error: `"${p.title}" can't be bought here.` }, 400);
      if (!(Number(p.price) > 0)) return json({ error: `"${p.title}" has no price.` }, 400);
      let variant: string | null = it.variant ?? null;
      if (Array.isArray(p.variants) && p.variants.length) {
        if (!p.variants.includes(variant)) return json({ error: `Pick a ${(p.variant_label || 'size').toLowerCase()} for "${p.title}".` }, 400);
      } else variant = null;
      const qty = Math.floor(Number(it.qty));
      if (!(qty >= 1 && qty <= MAX_QTY)) return json({ error: 'Bad quantity.' }, 400);
      const sku = variant ? `${p.id}:${variant}` : p.id;
      const prev = merged.get(sku);
      merged.set(sku, { sku, id: p.id, variant, qty: (prev?.qty || 0) + qty, product: p });
    }
    const lines = [...merged.values()];
    if (lines.some((l) => l.qty > MAX_QTY)) return json({ error: `Max ${MAX_QTY} of any one item.` }, 400);

    const supa = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);

    // Stock check (no row = untracked/unlimited)
    const { data: stock, error: se } = await supa.from('shop_stock').select('sku,qty').in('sku', lines.map((l) => l.sku));
    if (se) throw se;
    const left = new Map<string, number>((stock || []).map((s: any) => [s.sku, s.qty]));
    for (const l of lines) {
      if (left.has(l.sku) && left.get(l.sku)! < l.qty) {
        const n = left.get(l.sku)!;
        return json({ error: n > 0 ? `Only ${n} left of ${labelOf(l)}.` : `${labelOf(l)} is sold out.` }, 409);
      }
    }

    // Pending order row
    const orderId = crypto.randomUUID();
    const orderItems = lines.map((l) => ({
      sku: l.sku, id: l.id, variant: l.variant, qty: l.qty, title: l.product.title,
      unit_amount: Math.round(Number(l.product.price) * 100),
    }));
    const { error: oe } = await supa.from('shop_orders').insert({ id: orderId, status: 'pending', items: orderItems, region });
    if (oe) throw oe;

    const params: Record<string, unknown> = {
      mode: 'payment',
      client_reference_id: orderId,
      metadata: { kind: 'shop', order_id: orderId },
      payment_intent_data: { metadata: { kind: 'shop', order_id: orderId } },
      line_items: lines.map((l) => {
        const img = (Array.isArray(l.product.images) && l.product.images[0]) || l.product.image || '';
        const imgName = String(img).replace(/^\.\//, '');
        return {
          quantity: l.qty,
          price_data: {
            currency: 'cad',
            unit_amount: Math.round(Number(l.product.price) * 100),
            product_data: {
              name: labelOf(l),
              images: imgName ? [/^https?:/.test(imgName) ? imgName : IMG_BASE + imgName] : undefined,
              metadata: { sku: l.sku },
            },
          },
        };
      }),
      shipping_options: [{
        shipping_rate_data: { type: 'fixed_amount', display_name: ship.name, fixed_amount: { amount: ship.amount, currency: 'cad' } },
      }],
      success_url: SITE + '/shoppe/?order=success',
      cancel_url: SITE + '/shoppe/?order=cancel',
      expires_at: Math.floor(Date.now() / 1000) + 30 * 60,
    };
    if (ship.countries) params.shipping_address_collection = { allowed_countries: ship.countries };
    else params.phone_number_collection = { enabled: true };

    const r = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + Deno.env.get('STRIPE_SECRET_KEY'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: form(params),
    });
    const s = await r.json();
    if (!r.ok) {
      console.error('stripe error', s);
      await supa.from('shop_orders').update({ status: 'error' }).eq('id', orderId);
      return json({ error: 'Payment setup failed. Try again in a minute.' }, 502);
    }
    await supa.from('shop_orders').update({ stripe_session_id: s.id }).eq('id', orderId);
    return json({ url: s.url });
  } catch (e) {
    console.error('create-checkout', e);
    return json({ error: 'Something went wrong. Try again.' }, 500);
  }
});
