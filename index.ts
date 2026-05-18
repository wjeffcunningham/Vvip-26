// supabase/functions/upload-pool/index.ts
// Deploy: supabase functions deploy upload-pool --project-ref fyyfiimnltaktrsczjdq --use-api --workdir ~/Documents/GitHub/VVIP25
//
// Handles two operations:
//   POST  → upload image(s) to R2 MEDIA/pool/
//   GET ?action=list → return list of pool images
//
// Secrets needed (same as upload-thumb):
//   CF_ACCOUNT_ID, CF_R2_ACCESS_KEY, CF_R2_SECRET_KEY, CF_R2_BUCKET

import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { S3Client, PutObjectCommand, ListObjectsV2Command } from 'https://esm.sh/@aws-sdk/client-s3@3';

const BUCKET  = Deno.env.get('CF_R2_BUCKET')!;
const CDN_URL = 'https://cdn.vvipmedia.net';
const POOL_PREFIX = 'MEDIA/pool/';

const s3 = new S3Client({
  region: 'auto',
  endpoint: `https://${Deno.env.get('CF_ACCOUNT_ID')}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId:     Deno.env.get('CF_R2_ACCESS_KEY')!,
    secretAccessKey: Deno.env.get('CF_R2_SECRET_KEY')!,
  },
});

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, content-type',
};

serve(async (req) => {
  if(req.method === 'OPTIONS') return new Response('ok', { headers: cors });

  // Auth check — must be logged in (admin check happens at manifest level)
  const authHeader = req.headers.get('Authorization');
  if(!authHeader) return new Response('Unauthorized', { status: 401, headers: cors });

  const supa = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  );
  const token = authHeader.replace('Bearer ', '');
  const { data: { user } } = await supa.auth.getUser(token);
  if(!user) return new Response('Unauthorized', { status: 401, headers: cors });

  // Verify admin
  const { data: profile } = await supa.from('profiles').select('is_admin').eq('id', user.id).single();
  if(!profile?.is_admin) return new Response('Forbidden', { status: 403, headers: cors });

  // ── GET: list pool ──
  if(req.method === 'GET') {
    const url = new URL(req.url);
    if(url.searchParams.get('action') === 'list') {
      try {
        const res = await s3.send(new ListObjectsV2Command({
          Bucket: BUCKET,
          Prefix: POOL_PREFIX,
          MaxKeys: 500,
        }));
        const files = (res.Contents || [])
          .filter(obj => obj.Key && !obj.Key.endsWith('/'))
          .map(obj => {
            const name = obj.Key!.replace(POOL_PREFIX, '');
            return { name, url: `${CDN_URL}/${obj.Key}`, size: obj.Size };
          })
          .sort((a, b) => b.name.localeCompare(a.name)); // newest first (date-prefixed names)
        return new Response(JSON.stringify({ files }), {
          headers: { ...cors, 'Content-Type': 'application/json' },
        });
      } catch(e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: cors });
      }
    }
  }

  // ── POST: upload to pool ──
  if(req.method === 'POST') {
    try {
      const formData = await req.formData();
      const file = formData.get('file') as File;
      if(!file) return new Response('No file', { status: 400, headers: cors });

      const fileName = file.name; // already has date prefix if provided by client
      const key = POOL_PREFIX + fileName;
      const bytes = new Uint8Array(await file.arrayBuffer());
      const contentType = file.type || 'image/jpeg';

      await s3.send(new PutObjectCommand({
        Bucket: BUCKET,
        Key: key,
        Body: bytes,
        ContentType: contentType,
      }));

      return new Response(JSON.stringify({
        ok: true,
        name: fileName,
        url: `${CDN_URL}/${key}`,
      }), {
        headers: { ...cors, 'Content-Type': 'application/json' },
      });
    } catch(e) {
      console.error('upload-pool error:', e);
      return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: cors });
    }
  }

  return new Response('Method not allowed', { status: 405, headers: cors });
});
