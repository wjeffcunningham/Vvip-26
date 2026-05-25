// Supabase Edge Function: update-manifest
// Writes manifest.json to Cloudflare R2. Supports two actions:
//   { tracks: [...] }           — full replace (from Edit/Upload panes)
//   { action: "patch", track }  — patch single track (from Hashtags pane)
// Deploy: supabase functions deploy update-manifest --project-ref fyyfiimnltaktrsczjdq --use-api

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

    let tracks: unknown[];

    if (body.action === "patch" && body.track) {
      // Fetch current manifest, apply patch for one track
      const getRes = await r2.fetch(`${endpoint}/${bucket}/manifest.json`);
      if (!getRes.ok) return json({ error: "Could not fetch current manifest" }, 502);
      const current = await getRes.json() as unknown[];
      const data = Array.isArray(current) ? current : (current as Record<string,unknown>).tracks as unknown[] || [];
      const idx = data.findIndex((t: unknown) => (t as Record<string,unknown>).name === (body.track as Record<string,unknown>).name);
      if (idx >= 0) {
        data[idx] = { ...(data[idx] as object), ...(body.track as object) };
      } else {
        data.push(body.track);
      }
      tracks = data;
    } else if (Array.isArray(body.tracks)) {
      tracks = body.tracks;
    } else {
      return json({ error: "Provide either { tracks: [...] } or { action: 'patch', track: {...} }" }, 400);
    }

    // 4. Write manifest.json to R2
    const putRes = await r2.fetch(`${endpoint}/${bucket}/manifest.json`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(tracks),
    });

    if (!putRes.ok) {
      const txt = await putRes.text();
      return json({ error: "R2 write failed: " + txt }, 502);
    }

    return json({ ok: true, count: tracks.length });

  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
