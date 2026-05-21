// Supabase Edge Function: admin-set-role
// Sets is_admin or is_premium on a profile by email. Caller must be admin.
// Also supports listing all users (action: "list").
// Deploy: supabase functions deploy admin-set-role --project-ref fyyfiimnltaktrsczjdq --use-api

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

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
    // 1. Auth — caller must be logged in
    const token = (req.headers.get("Authorization") || "").replace("Bearer ", "");
    if (!token) return json({ error: "Unauthorized" }, 401);

    const supa = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );
    const { data: { user }, error: authErr } = await supa.auth.getUser(token);
    if (authErr || !user) return json({ error: "Unauthorized" }, 401);

    // 2. Caller must be admin
    const { data: callerProfile } = await supa
      .from("profiles")
      .select("is_admin")
      .eq("id", user.id)
      .single();
    if (!callerProfile?.is_admin) return json({ error: "Forbidden — admins only" }, 403);

    // 3. Parse request
    const body = await req.json();
    const action = body.action as string | undefined;

    // ── LIST ALL USERS ──
    if (action === "list") {
      const { data: profiles, error } = await supa
        .from("profiles")
        .select("id, username, is_admin, is_premium");
      if (error) return json({ error: error.message }, 500);

      // Enrich with emails from auth.users via admin API
      const { data: authUsers } = await supa.auth.admin.listUsers({ perPage: 1000 });
      const emailMap: Record<string, string> = {};
      for (const u of (authUsers?.users || [])) {
        emailMap[u.id] = u.email || "";
      }

      const enriched = (profiles || []).map(p => ({
        ...p,
        email: emailMap[p.id] || "",
      }));

      return json({ users: enriched });
    }

    // ── SET ROLE ──
    const email  = (body.email as string | undefined)?.trim().toLowerCase();
    const field  = body.field  as string | undefined; // "is_admin" | "is_premium"
    const value  = body.value  as boolean | undefined;

    if (!email || !field || value === undefined) {
      return json({ error: "Provide email, field (is_admin|is_premium), value (true|false)" }, 400);
    }
    if (!["is_admin", "is_premium"].includes(field)) {
      return json({ error: "field must be is_admin or is_premium" }, 400);
    }

    // Look up user by email via admin API
    const { data: authUsers } = await supa.auth.admin.listUsers({ perPage: 1000 });
    const target = (authUsers?.users || []).find(u => u.email?.toLowerCase() === email);
    if (!target) return json({ error: `No user found with email: ${email}` }, 404);

    // Upsert profile with the new role value
    const { error: upsertErr } = await supa
      .from("profiles")
      .upsert({ id: target.id, [field]: value }, { onConflict: "id" });

    if (upsertErr) return json({ error: upsertErr.message }, 500);

    return json({ ok: true, email, field, value, userId: target.id });

  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
