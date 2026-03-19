import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const adminClient = createClient(supabaseUrl, serviceRoleKey);

    // Check if any admin already exists
    const { data: existingAdmins } = await adminClient
      .from("employees")
      .select("id")
      .eq("role", "admin")
      .limit(1);

    if (existingAdmins && existingAdmins.length > 0) {
      return new Response(
        JSON.stringify({ error: "An admin account already exists. Please sign in or contact your administrator." }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { name, email, password, department } = await req.json();

    if (!name || !email || !password) {
      return new Response(
        JSON.stringify({ error: "Name, email, and password are required." }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (password.length < 8) {
      return new Response(
        JSON.stringify({ error: "Password must be at least 8 characters." }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Create auth user
    const { data: authData, error: authError } = await adminClient.auth.admin.createUser({
      email: email.toLowerCase(),
      password,
      email_confirm: true,
      user_metadata: { name, role: "admin" },
    });

    if (authError) {
      return new Response(
        JSON.stringify({ error: authError.message }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const initials = name.split(" ").map((w: string) => w[0]).join("").toUpperCase().slice(0, 2);
    const empId = "admin" + Date.now().toString(36);

    const { error: empError } = await adminClient.from("employees").insert({
      id: empId,
      name,
      email: email.toLowerCase(),
      department: department || "Administration",
      role: "admin",
      avatar: initials,
      auth_user_id: authData.user.id,
    });

    if (empError) {
      await adminClient.auth.admin.deleteUser(authData.user.id);
      return new Response(
        JSON.stringify({ error: "Failed to create admin record: " + empError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    return new Response(
      JSON.stringify({ ok: true, message: "Admin account created successfully." }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ error: err.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
