// Supabase Edge Function: admin-set-role
// Sets is_admin or is_premium on a user by email. Admin only.
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
};

serve(async (req) => {
  if(req.method === "OPTIONS") return json({ok:true}, 200);
  try {
    const token = (req.headers.get("Authorization")||"").replace("Bearer ","");
    if(!token) return json({error:"Unauthorized"}, 401);

    const supa = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // Verify caller is admin
    const { data:{ user }, error:authErr } = await supa.auth.getUser(token);
    if(authErr || !user) return json({error:"Unauthorized"}, 401);
    const { data: callerProfile } = await supa.from("profiles").select("is_admin").eq("id", user.id).single();
    if(!callerProfile?.is_admin) return json({error:"Admins only"}, 403);

    const body = await req.json();

    // List users action
    if(body.action === "list"){
      const { data: { users } } = await supa.auth.admin.listUsers({ perPage: 200 });
      const ids = users.map(u => u.id);
      const { data: profiles } = await supa.from("profiles").select("id,is_admin,is_premium").in("id", ids);
      const pMap = Object.fromEntries((profiles||[]).map(p=>[p.id,p]));
      return json({ users: users.map(u=>({
        id: u.id,
        email: u.email,
        is_admin: pMap[u.id]?.is_admin || false,
        is_premium: pMap[u.id]?.is_premium || false,
        created_at: u.created_at,
      }))});
    }

    // Set role action
    const { email, field, value } = body;
    if(!email || !field) return json({error:"Missing email or field"}, 400);
    if(!["is_admin","is_premium"].includes(field)) return json({error:"Invalid field"}, 400);

    // Find user by email
    const { data: { users } } = await supa.auth.admin.listUsers({ perPage: 200 });
    const target = users.find(u => u.email?.toLowerCase() === email.toLowerCase());
    if(!target) return json({error:"User not found: " + email}, 404);

    // Upsert profile
    const { error: upErr } = await supa.from("profiles")
      .upsert({ id: target.id, [field]: value });
    if(upErr) return json({error: upErr.message}, 500);

    return json({ ok: true, email, field, value });
  } catch(e) {
    return json({ error: String(e) }, 500);
  }
});

function json(data: unknown, status=200){
  return new Response(JSON.stringify(data), {
    status, headers: {...CORS, "Content-Type":"application/json"}
  });
}
