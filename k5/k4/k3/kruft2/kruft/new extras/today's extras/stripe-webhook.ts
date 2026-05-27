// Supabase Edge Function: stripe-webhook
// Listens for Stripe checkout.session.completed -> sets is_premium=true
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import Stripe from "https://esm.sh/stripe@12.18.0?target=deno";

serve(async (req) => {
  const signature = req.headers.get("stripe-signature");
  const body = await req.text();
  const webhookSecret = Deno.env.get("STRIPE_WEBHOOK_SECRET")!;
  const stripeKey = Deno.env.get("STRIPE_SECRET_KEY")!;

  let event: Stripe.Event;
  try {
    const stripe = new Stripe(stripeKey, { apiVersion: "2023-10-16", httpClient: Stripe.createFetchHttpClient() });
    event = await stripe.webhooks.constructEventAsync(body, signature!, webhookSecret);
  } catch (err) {
    console.error("Webhook signature verification failed:", err);
    return new Response("Webhook Error: " + err.message, { status: 400 });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object as Stripe.Checkout.Session;
    // Get customer email from session
    const email = session.customer_details?.email || session.customer_email;
    if (!email) {
      console.error("No email in session", session.id);
      return new Response("No email", { status: 200 });
    }

    const supa = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // Find user by email
    const { data: users } = await supa.auth.admin.listUsers();
    const user = users?.users?.find(u => u.email?.toLowerCase() === email.toLowerCase());

    if (!user) {
      // User hasn't signed up yet — store pending premium by email for when they do
      await supa.from("pending_premium").upsert({ email: email.toLowerCase(), stripe_session: session.id });
      console.log("Stored pending premium for", email);
      return new Response("Pending", { status: 200 });
    }

    // Set is_premium = true
    const { error } = await supa
      .from("profiles")
      .upsert({ id: user.id, is_premium: true, stripe_customer_id: String(session.customer || "") });

    if (error) {
      console.error("Failed to set premium:", error);
      return new Response("DB error", { status: 500 });
    }

    console.log("Premium activated for", email);
  }

  return new Response("ok", { status: 200 });
});
