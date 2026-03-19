import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const DEMO_USERS = [
  { id: "admin1", email: "admin@corp.com", password: "Admin@1234", name: "Sarah Mitchell", department: "Administration", avatar: "SM", role: "admin" },
  { id: "tl1", email: "tl.james@corp.com", password: "James@1234", name: "James Harrison", department: "Networking", avatar: "JH", role: "tl" },
  { id: "tl2", email: "tl.layla@corp.com", password: "Layla@1234", name: "Layla Al Mansoori", department: "CCTV", avatar: "LM", role: "tl" },
  { id: "e1", email: "m.webb@corp.com", password: "Marcus@1234", name: "Marcus Webb", department: "IT", avatar: "MW", role: "employee" },
  { id: "e2", email: "p.sharma@corp.com", password: "Priya@1234", name: "Priya Sharma", department: "Networking", avatar: "PS", role: "employee" },
  { id: "e3", email: "d.okafor@corp.com", password: "Daniel@1234", name: "Daniel Okafor", department: "CCTV", avatar: "DO", role: "employee" },
  { id: "e4", email: "s.reyes@corp.com", password: "Sofia@1234", name: "Sofia Reyes", department: "Security", avatar: "SR", role: "employee" },
  { id: "e5", email: "a.chen@corp.com", password: "Alex@1234", name: "Alex Chen", department: "Maintenance", avatar: "AC", role: "employee" },
];

Deno.serve(async (req) => {
  const supabaseAdmin = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { autoRefreshToken: false, persistSession: false } }
  );

  const results: any[] = [];

  for (const user of DEMO_USERS) {
    // Check if user already exists
    const { data: existing } = await supabaseAdmin.auth.admin.listUsers();
    const found = existing?.users?.find((u: any) => u.email === user.email);

    if (found) {
      // Link auth user to employee record
      await supabaseAdmin
        .from("employees")
        .update({ auth_user_id: found.id })
        .eq("id", user.id);
      results.push({ email: user.email, status: "exists", auth_id: found.id });
      continue;
    }

    // Create auth user
    const { data: created, error } = await supabaseAdmin.auth.admin.createUser({
      email: user.email,
      password: user.password,
      email_confirm: true,
    });

    if (error) {
      results.push({ email: user.email, status: "error", error: error.message });
      continue;
    }

    // Link auth user to employee record
    if (created?.user) {
      await supabaseAdmin
        .from("employees")
        .update({ auth_user_id: created.user.id })
        .eq("id", user.id);
    }

    results.push({ email: user.email, status: "created", auth_id: created?.user?.id });
  }

  return new Response(JSON.stringify({ results }), {
    headers: { "Content-Type": "application/json" },
  });
});
