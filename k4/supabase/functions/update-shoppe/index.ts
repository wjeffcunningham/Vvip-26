// Supabase Edge Function: update-shoppe
// Receives updated items array, writes shoppe/shoppe.json to Cloudflare R2
// Deploy: supabase functions deploy update-shoppe --project-ref fyyfiimnltaktrsczjdq --use-api

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { AwsClient } from "https://esm.sh/aws4fetch@1.0.17";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  try {
    // 1. Auth
    const token = (req.headers.get("Authorization") || "").replace("Bearer ", "");
    if (!token) return json({ error: "Unauthorized" }, 401);

    const supa = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );
    const { data: { user }, error: authErr } = await supa.auth.getUser(token);
    if (authErr || !user) return json({ error: "Unauthorized" }, 401);

    // 2. Admin check
    const { data: profile } = await supa
      .from("profiles")
      .select("is_admin")
      .eq("id", user.id)
      .single();
    if (!profile?.is_admin) return json({ error: "Forbidden" }, 403);

    // 3. Parse body
    const body = await req.json();
    const items = body.items;
    if (!Array.isArray(items)) return json({ error: "items must be an array" }, 400);

    // 4. Write to R2 at shoppe/shoppe.json
    const accountId = Deno.env.get("CLOUDFLARE_ACCOUNT_ID")!;
    const accessKey = Deno.env.get("R2_ACCESS_KEY_ID")!;
    const secretKey = Deno.env.get("R2_SECRET_ACCESS_KEY")!;
    const bucket    = Deno.env.get("R2_BUCKET_NAME")!;
    const endpoint  = `https://${accountId}.r2.cloudflarestorage.com`;

    const r2 = new AwsClient({
      accessKeyId: accessKey,
      secretAccessKey: secretKey,
      service: "s3",
      region: "auto",
    });

    const payload = { items, updatedAt: new Date().toISOString() };

    const putRes = await r2.fetch(`${endpoint}/${bucket}/shoppe/shoppe.json`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!putRes.ok) {
      const txt = await putRes.text();
      return json({ error: "R2 write failed: " + txt }, 502);
    }

    return json({ ok: true, count: items.length });

  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
