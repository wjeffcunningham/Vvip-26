// Supabase Edge Function: upload-extras
// Uploads gem images to MEDIA/extras/ and misc photos to MEDIA/misc/
// For gems: also patches the manifest extras array for that track
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
    const category  = (form.get("category") as string | null) || "misc"; // "gem" | "misc"
    const trackName = (form.get("trackName") as string | null) || "";
    const destPath  = form.get("destPath") as string | null; // full path from client

    if (!file) return json({ error: "Missing file" }, 400);

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

    // 4. Determine upload path
    const ext = file.name.split(".").pop()?.toLowerCase() || "jpg";
    const contentType = ext === "png" ? "image/png" : ext === "webp" ? "image/webp" : "image/jpeg";
    const ts = Date.now();

    let uploadPath: string;
    if (destPath) {
      uploadPath = destPath;
    } else if (category === "gem" && trackName) {
      const base = trackName.replace(/\.[^.]+$/, "").toLowerCase().replace(/\s+/g, "-");
      uploadPath = `MEDIA/extras/${base}-gem-${ts}.${ext}`;
    } else {
      uploadPath = `MEDIA/misc/${ts}-${file.name.replace(/\s+/g, "-")}`;
    }

    const filename = uploadPath.split("/").pop()!;

    // 5. Upload file
    const imageBytes = await file.arrayBuffer();
    const putRes = await r2.fetch(`${endpoint}/${bucket}/${uploadPath}`, {
      method: "PUT",
      headers: { "Content-Type": contentType },
      body: imageBytes,
    });
    if (!putRes.ok) {
      const txt = await putRes.text();
      return json({ error: "Upload failed: " + txt }, 502);
    }

    // 6. For gems: patch manifest to add this file to track's extras array
    if (category === "gem" && trackName) {
      try {
        const mRes = await r2.fetch(`${endpoint}/${bucket}/manifest.json`);
        if (mRes.ok) {
          const manifest = await mRes.json() as Record<string, unknown>[];
          const idx = manifest.findIndex(t => t.name === trackName);
          if (idx >= 0) {
            const existing = (manifest[idx].extras as string[] | undefined) || [];
            if (!existing.includes(filename)) {
              manifest[idx] = { ...manifest[idx], extras: [...existing, filename] };
              await r2.fetch(`${endpoint}/${bucket}/manifest.json`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(manifest),
              });
            }
          }
        }

        // Also patch extras.json if it exists
        try {
          const exRes = await r2.fetch(`${endpoint}/${bucket}/extras.json`);
          if (exRes.ok) {
            const extrasMap = await exRes.json() as Record<string, string[]>;
            const key = trackName.replace(/\.[^.]+$/, "");
            const arr = extrasMap[key] || [];
            if (!arr.includes(filename)) {
              extrasMap[key] = [...arr, filename];
              await r2.fetch(`${endpoint}/${bucket}/extras.json`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(extrasMap),
              });
            }
          }
        } catch (_) { /* extras.json optional */ }

      } catch (_) {
        // manifest patch failure is non-fatal — image is uploaded
      }
    }

    return json({ ok: true, path: uploadPath, filename, category });

  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
