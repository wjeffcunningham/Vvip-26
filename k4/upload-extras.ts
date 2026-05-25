// Supabase Edge Function: upload-extras
// Receives a multipart form upload, stores the file in R2 at MEDIA/extras/
// and updates extras.json to register the gem against the track.
// Deploy: supabase functions deploy upload-extras --project-ref fyyfiimnltaktrsczjdq --use-api

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

    const { data: profile } = await supa
      .from("profiles")
      .select("is_admin")
      .eq("id", user.id)
      .single();
    if (!profile?.is_admin) return json({ error: "Forbidden" }, 403);

    // 2. Parse multipart form
    const form = await req.formData();
    const file     = form.get("file") as File | null;
    const trackName = (form.get("trackName") as string || "").trim();
    const destName  = (form.get("destName")  as string || "").trim();

    if (!file)      return json({ error: "No file provided" }, 400);
    if (!trackName) return json({ error: "trackName required" }, 400);
    if (!destName)  return json({ error: "destName required" }, 400);

    const accountId = Deno.env.get("CLOUDFLARE_ACCOUNT_ID")!;
    const accessKey = Deno.env.get("R2_ACCESS_KEY_ID")!;
    const secretKey = Deno.env.get("R2_SECRET_ACCESS_KEY")!;
    const bucket    = Deno.env.get("R2_BUCKET_NAME")!;

    const endpoint = `https://${accountId}.r2.cloudflarestorage.com`;
    const aws = new AwsClient({ accessKeyId: accessKey, secretAccessKey: secretKey });

    // 3. Upload image/video to MEDIA/extras/
    const fileBytes = await file.arrayBuffer();
    const r2FileUrl = `${endpoint}/${bucket}/MEDIA/extras/${destName}`;

    const uploadRes = await aws.fetch(r2FileUrl, {
      method: "PUT",
      headers: {
        "Content-Type": file.type || "application/octet-stream",
        "Cache-Control": "public, max-age=31536000",
      },
      body: fileBytes,
    });

    if (!uploadRes.ok) {
      const msg = await uploadRes.text();
      return json({ error: "File upload failed: " + msg }, 502);
    }

    // 4. Fetch current extras.json, add entry, write back
    const extrasUrl = `${endpoint}/${bucket}/extras.json`;

    let extras: Record<string, string[]> = {};
    try {
      const existing = await aws.fetch(extrasUrl, { method: "GET" });
      if (existing.ok) extras = await existing.json();
    } catch { /* first gem — extras.json doesn't exist yet */ }

    // Key is track base name (no extension, lowercase)
    const base = trackName.replace(/\.[^.]+$/, "").toLowerCase();
    if (!extras[base]) extras[base] = [];
    if (!extras[base].includes(destName)) extras[base].push(destName);

    const extrasWriteRes = await aws.fetch(extrasUrl, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache, no-store",
      },
      body: JSON.stringify(extras, null, 2),
    });

    if (!extrasWriteRes.ok) {
      // File uploaded fine, just extras.json update failed — warn but don't fail
      console.warn("extras.json update failed:", await extrasWriteRes.text());
      return json({ ok: true, destName, warning: "extras.json not updated" });
    }

    return json({ ok: true, destName, base });
  } catch (e) {
    console.error("upload-extras error:", e);
    return json({ error: String(e) }, 500);
  }
});
