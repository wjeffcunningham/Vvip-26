// Supabase Edge Function: upload-thumb
// Uploads an image to R2 at assets/thumbs/ AND updates thumbs.json
// Accepts category field: "primary" | "override" — both go to assets/thumbs/
// Deploy: supabase functions deploy upload-thumb --project-ref fyyfiimnltaktrsczjdq --use-api

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

    // 3. Parse multipart form
    const form = await req.formData();
    const file      = form.get("file") as File;
    const thumbName = form.get("thumbName") as string;
    const trackName = form.get("trackName") as string | null;
    const category  = (form.get("category") as string | null) || "primary";

    if (!file || !thumbName) return json({ error: "Missing file or thumbName" }, 400);

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

    // 4. Upload image to assets/thumbs/
    const imageBytes = await file.arrayBuffer();
    const ext = thumbName.split(".").pop()?.toLowerCase() || "jpg";
    const contentType = ext === "png" ? "image/png" : ext === "webp" ? "image/webp" : "image/jpeg";

    const uploadPath = `assets/thumbs/${thumbName}`;
    const putRes = await r2.fetch(`${endpoint}/${bucket}/${uploadPath}`, {
      method: "PUT",
      headers: { "Content-Type": contentType },
      body: imageBytes,
    });
    if (!putRes.ok) {
      const txt = await putRes.text();
      return json({ error: "Image upload failed: " + txt }, 502);
    }

    // 5. Update thumbs.json — add thumbName if not already listed
    try {
      const thumbsRes = await r2.fetch(`${endpoint}/${bucket}/thumbs.json`);
      let thumbsList: string[] = [];
      if (thumbsRes.ok) {
        thumbsList = await thumbsRes.json() as string[];
      }
      if (!thumbsList.includes(thumbName)) {
        thumbsList.push(thumbName);
        await r2.fetch(`${endpoint}/${bucket}/thumbs.json`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(thumbsList),
        });
      }
    } catch (_) {
      // thumbs.json update failure is non-fatal — image is already uploaded
    }

    // 6. If this is an override thumb and trackName provided, patch manifest to record it
    if (category === "override" && trackName) {
      try {
        const mRes = await r2.fetch(`${endpoint}/${bucket}/manifest.json`);
        if (mRes.ok) {
          const manifest = await mRes.json() as Record<string, unknown>[];
          const idx = manifest.findIndex(t => t.name === trackName);
          if (idx >= 0) {
            manifest[idx] = { ...manifest[idx], thumb: thumbName };
            await r2.fetch(`${endpoint}/${bucket}/manifest.json`, {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(manifest),
            });
          }
        }
      } catch (_) {
        // manifest patch failure is non-fatal
      }
    }

    return json({ ok: true, path: uploadPath, thumbName, category });

  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
