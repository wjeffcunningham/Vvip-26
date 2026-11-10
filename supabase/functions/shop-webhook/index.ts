// shop-webhook — Stripe → marks shop orders paid + decrements stock.
// Separate from the existing stripe-webhook (VVIP+ membership) so that one is untouched.
// Deploy: Dashboard → Edge Functions → new function "shop-webhook" → paste → turn OFF "Enforce JWT verification".
// Secret needed: STRIPE_SHOP_WEBHOOK_SECRET (the whsec_... from the Stripe webhook endpoint you create for this URL).

import { createClient } from 'npm:@supabase/supabase-js@2';

const te = new TextEncoder();

async function verify(raw: string, header: string, secret: string): Promise<boolean> {
  if (!header || !secret) return false;
  let t = '';
  const sigs: string[] = [];
  for (const part of header.split(',')) {
    const i = part.indexOf('=');
    const k = part.slice(0, i), v = part.slice(i + 1);
    if (k === 't') t = v; else if (k === 'v1') sigs.push(v);
  }
  if (!t || !sigs.length) return false;
  if (Math.abs(Date.now() / 1000 - Number(t)) > 300) return false;
  const key = await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, te.encode(`${t}.${raw}`)));
  const hex = [...mac].map((b) => b.toString(16).padStart(2, '0')).join('');
  return sigs.some((s) => {
    if (s.length !== hex.length) return false;
    let d = 0;
    for (let i = 0; i < s.length; i++) d |= s.charCodeAt(i) ^ hex.charCodeAt(i);
    return d === 0;
  });
}

Deno.serve(async (req) => {
  if (req.method !== 'POST') return new Response('POST only', { status: 405 });
  const raw = await req.text();
  const ok = await verify(raw, req.headers.get('stripe-signature') || '', Deno.env.get('STRIPE_SHOP_WEBHOOK_SECRET') || '');
  if (!ok) return new Response('bad signature', { status: 400 });

  const event = JSON.parse(raw);
  const s = event?.data?.object;
  if (s?.metadata?.kind !== 'shop' || !s?.metadata?.order_id) return new Response('ignored', { status: 200 });
  const orderId = s.metadata.order_id;
  const supa = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);

  try {
    if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
      if (s.payment_status !== 'paid') return new Response('awaiting payment', { status: 200 });
      const ship = s.collected_information?.shipping_details || s.shipping_details || null;
      const { data, error } = await supa.rpc('shop_fulfil', {
        p_order_id: orderId,
        p_session: s.id,
        p_email: s.customer_details?.email ?? null,
        p_name: ship?.name ?? s.customer_details?.name ?? null,
        p_phone: s.customer_details?.phone ?? null,
        p_shipping: ship?.address ?? null,
        p_amount: s.amount_total ?? null,
        p_currency: s.currency ?? null,
      });
      if (error) throw error;
      return new Response(data ? 'fulfilled' : 'already fulfilled', { status: 200 });
    }
    if (event.type === 'checkout.session.expired') {
      await supa.from('shop_orders').update({ status: 'expired' }).eq('id', orderId).eq('status', 'pending');
      return new Response('expired', { status: 200 });
    }
    return new Response('ignored', { status: 200 });
  } catch (e) {
    console.error('shop-webhook', e);
    return new Response('error', { status: 500 }); // Stripe will retry
  }
});
