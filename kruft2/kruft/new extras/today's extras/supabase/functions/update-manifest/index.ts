// Supabase Edge Function: update-manifest
// Receives updated tracks array, writes manifest.json to Cloudflare R2
// Deploy: supabase functions deploy update-manifest

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// ── R2 config — set these in Supabase Dashboard → Edge Functions → Secrets ──
// CLOUDFLARE_ACCOUNT_ID
// R2_ACCESS_KEY_ID
// R2_SECRET_ACCESS_KEY
// R2_BUCKET_NAME          (e.g. vvipmedia)
// R2_PUBLIC_URL           (e.g. https://vvipmedia.net)  — used to verify

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
};

serve(async (req) => {
  if(req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  try {
    // 1. Auth — must be a logged-in admin
    const authHeader = req.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    if(!token) return json({ error: "Unauthorized" }, 401);

    const supa = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const { data: { user }, error: authErr } = await supa.auth.getUser(token);
    if(authErr || !user) return json({ error: "Unauthorized" }, 401);

    // 2. Verify admin
    const { data: profile } = await supa
      .from("profiles")
      .select("is_admin")
      .eq("id", user.id)
      .single();

    if(!profile?.is_admin) return json({ error: "Forbidden — admins only" }, 403);

    // 3. Parse body
    const body = await req.json();
    const tracks = body.tracks;
    if(!Array.isArray(tracks)) return json({ error: "tracks must be an array" }, 400);

    // 4. Write to R2 via S3-compatible API
    const accountId  = Deno.env.get("1b818745728e858c0ee17bb80119076a")!;
    const accessKey  = Deno.env.get("11d7c9793eb522423a57370c4bf17335")!;
    const secretKey  = Deno.env.get("29ceea08c5a79754a6f2644c14e553c470fbc8f206a890add21032a1f8ad3ba1")!;
    const bucket     = Deno.env.get("vvip-media")!;

    const endpoint = `https://${accountId}.r2.cloudflarestorage.com`;
    const manifest = JSON.stringify({ tracks }, null, 2);
    const manifestBytes = new TextEncoder().encode(manifest);

    // AWS Sig V4 for R2
    const url = `${endpoint}/${bucket}/manifest.json`;
    const now = new Date();
    const dateStr = now.toISOString().replace(/[-:]/g,"").replace(/\..*/,"Z"); // YYYYMMDDTHHmmssZ
    const dateOnly = dateStr.slice(0,8); // YYYYMMDD

    const contentHash = await sha256hex(manifestBytes);

    const headers: Record<string,string> = {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "x-amz-content-sha256": contentHash,
      "x-amz-date": dateStr,
      "Host": `${accountId}.r2.cloudflarestorage.com`,
    };

    const sig = await signV4({
      method: "PUT",
      url,
      headers,
      body: manifestBytes,
      accessKey,
      secretKey,
      region: "auto",
      service: "s3",
      dateStr,
      dateOnly,
      contentHash,
    });

    headers["Authorization"] = sig;

    const r2res = await fetch(url, {
      method: "PUT",
      headers,
      body: manifestBytes,
    });

    if(!r2res.ok){
      const txt = await r2res.text();
      return json({ error: "R2 write failed", detail: txt }, 500);
    }

    // 5. Also update Supabase DB manifest table (optional backup)
    await supa.from("manifest_snapshots").insert({
      updated_by: user.id,
      track_count: tracks.length,
      snapshot: tracks,
    }).then(()=>{}).catch(()=>{});

    return json({ ok: true, tracks: tracks.length });

  } catch(e) {
    return json({ error: String(e) }, 500);
  }
});

function json(data: unknown, status = 200){
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

async function sha256hex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}

async function hmacSha256(key: ArrayBuffer | Uint8Array, data: string): Promise<ArrayBuffer> {
  const k = await crypto.subtle.importKey("raw", key, { name:"HMAC", hash:"SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", k, new TextEncoder().encode(data));
}

async function signV4({ method, url, headers, body, accessKey, secretKey, region, service, dateStr, dateOnly, contentHash }: {
  method:string; url:string; headers:Record<string,string>; body:Uint8Array;
  accessKey:string; secretKey:string; region:string; service:string;
  dateStr:string; dateOnly:string; contentHash:string;
}): Promise<string> {
  const parsedUrl = new URL(url);
  const canonicalUri = parsedUrl.pathname;
  const canonicalQuery = "";

  const signedHeaderKeys = ["content-type","host","x-amz-content-sha256","x-amz-date"]
    .filter(k => headers[k] || headers[k.replace(/-([a-z])/g,(_,c)=>c.toUpperCase())]);
  const allKeys = Object.keys(headers).map(k=>k.toLowerCase()).sort();
  const canonicalHeaders = allKeys.map(k=>`${k}:${headers[Object.keys(headers).find(h=>h.toLowerCase()===k)!]}\n`).join("");
  const signedHeaders = allKeys.join(";");

  const canonicalRequest = [method, canonicalUri, canonicalQuery, canonicalHeaders, signedHeaders, contentHash].join("\n");
  const credScope = `${dateOnly}/${region}/${service}/aws4_request`;
  const strToSign = ["AWS4-HMAC-SHA256", dateStr, credScope, await sha256hex(new TextEncoder().encode(canonicalRequest))].join("\n");

  let key: ArrayBuffer = new TextEncoder().encode("AWS4" + secretKey);
  for(const part of [dateOnly, region, service, "aws4_request"]){
    key = await hmacSha256(key, part);
  }
  const sig = await hmacSha256(key, strToSign);
  const sigHex = Array.from(new Uint8Array(sig)).map(b=>b.toString(16).padStart(2,"0")).join("");

  return `AWS4-HMAC-SHA256 Credential=${accessKey}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${sigHex}`;
}
