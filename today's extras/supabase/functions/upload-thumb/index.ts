// Supabase Edge Function: upload-thumb
// Uploads image to R2 at assets/thumbs/ AND updates thumbs.json
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  try {
    const token = (req.headers.get("Authorization") || "").replace("Bearer ", "");
    if (!token) return json({ error: "Unauthorized" }, 401);
    const supa = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const { data: { user }, error: authErr } = await supa.auth.getUser(token);
    if (authErr || !user) return json({ error: "Unauthorized" }, 401);
    const { data: profile } = await supa.from("profiles").select("is_admin").eq("id", user.id).single();
    if (!profile?.is_admin) return json({ error: "Admins only" }, 403);

    const form = await req.formData();
    const file = form.get("file") as File;
    const thumbName = form.get("thumbName") as string;
    if (!file || !thumbName) return json({ error: "Missing file or thumbName" }, 400);

    const accountId = Deno.env.get("CLOUDFLARE_ACCOUNT_ID")!;
    const accessKey = Deno.env.get("R2_ACCESS_KEY_ID")!;
    const secretKey = Deno.env.get("R2_SECRET_ACCESS_KEY")!;
    const bucket    = Deno.env.get("R2_BUCKET_NAME")!;

    // 1. Upload the image file to R2
    const bytes = new Uint8Array(await file.arrayBuffer());
    const contentType = file.type || "image/jpeg";
    await r2Put({ accountId, accessKey, secretKey, bucket,
      key: `assets/thumbs/${thumbName}`,
      body: bytes, contentType,
      cacheControl: "public, max-age=31536000" });

    // 2. Fetch current thumbs.json, add new entry if not already present
    let thumbsList: string[] = [];
    try {
      const existing = await r2Get({ accountId, accessKey, secretKey, bucket,
        key: "assets/thumbs/thumbs.json" });
      if (existing.ok) thumbsList = JSON.parse(await existing.text());
    } catch(_) {}

    if (!thumbsList.map(t => t.toLowerCase()).includes(thumbName.toLowerCase())) {
      thumbsList.push(thumbName);
    }

    // 3. Write updated thumbs.json back to R2
    const thumbsBytes = new TextEncoder().encode(JSON.stringify(thumbsList, null, 2));
    await r2Put({ accountId, accessKey, secretKey, bucket,
      key: "assets/thumbs/thumbs.json",
      body: thumbsBytes, contentType: "application/json",
      cacheControl: "no-store" });

    return json({ ok: true, path: `assets/thumbs/${thumbName}`, thumbsCount: thumbsList.length });
  } catch(e) { return json({ error: String(e) }, 500); }
});

async function r2Put({ accountId, accessKey, secretKey, bucket, key, body, contentType, cacheControl }: any) {
  const url = `https://${accountId}.r2.cloudflarestorage.com/${bucket}/${key}`;
  const now = new Date();
  const dateStr = now.toISOString().replace(/[-:]/g,"").replace(/\..*/,"Z");
  const dateOnly = dateStr.slice(0,8);
  const contentHash = await sha256hex(body);
  const hdrs: Record<string,string> = {
    "Content-Type": contentType, "Cache-Control": cacheControl,
    "x-amz-content-sha256": contentHash, "x-amz-date": dateStr,
    "Host": `${accountId}.r2.cloudflarestorage.com`,
  };
  hdrs["Authorization"] = await signV4({ method:"PUT", url, headers:hdrs, body, accessKey, secretKey, region:"auto", service:"s3", dateStr, dateOnly, contentHash });
  const res = await fetch(url, { method:"PUT", headers:hdrs, body });
  if (!res.ok) throw new Error(`R2 PUT failed for ${key}: ${await res.text()}`);
}

async function r2Get({ accountId, accessKey, secretKey, bucket, key }: any) {
  const url = `https://${accountId}.r2.cloudflarestorage.com/${bucket}/${key}`;
  const now = new Date();
  const dateStr = now.toISOString().replace(/[-:]/g,"").replace(/\..*/,"Z");
  const dateOnly = dateStr.slice(0,8);
  const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const hdrs: Record<string,string> = {
    "x-amz-content-sha256": emptyHash, "x-amz-date": dateStr,
    "Host": `${accountId}.r2.cloudflarestorage.com`,
  };
  hdrs["Authorization"] = await signV4({ method:"GET", url, headers:hdrs, body:new Uint8Array(0), accessKey, secretKey, region:"auto", service:"s3", dateStr, dateOnly, contentHash:emptyHash });
  return fetch(url, { method:"GET", headers:hdrs });
}

function json(data: unknown, status=200) {
  return new Response(JSON.stringify(data), { status, headers:{...CORS,"Content-Type":"application/json"} });
}
async function sha256hex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function hmacSha256(key: ArrayBuffer|Uint8Array, data: string): Promise<ArrayBuffer> {
  const k = await crypto.subtle.importKey("raw", key, {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  return crypto.subtle.sign("HMAC", k, new TextEncoder().encode(data));
}
async function signV4({method,url,headers,body,accessKey,secretKey,region,service,dateStr,dateOnly,contentHash}: any): Promise<string> {
  const parsedUrl = new URL(url);
  const allKeys = Object.keys(headers).map(k=>k.toLowerCase()).sort();
  const canonicalHeaders = allKeys.map(k=>`${k}:${headers[Object.keys(headers).find(h=>h.toLowerCase()===k)!]}\n`).join("");
  const signedHeaders = allKeys.join(";");
  const canonicalRequest = [method, parsedUrl.pathname, "", canonicalHeaders, signedHeaders, contentHash].join("\n");
  const credScope = `${dateOnly}/${region}/${service}/aws4_request`;
  const strToSign = ["AWS4-HMAC-SHA256", dateStr, credScope, await sha256hex(new TextEncoder().encode(canonicalRequest))].join("\n");
  let key: ArrayBuffer = new TextEncoder().encode("AWS4"+secretKey);
  for (const part of [dateOnly, region, service, "aws4_request"]) key = await hmacSha256(key, part);
  const sig = await hmacSha256(key, strToSign);
  const sigHex = Array.from(new Uint8Array(sig)).map(b=>b.toString(16).padStart(2,"0")).join("");
  return `AWS4-HMAC-SHA256 Credential=${accessKey}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${sigHex}`;
}
