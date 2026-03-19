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
    // Verify the caller is authenticated and is an admin
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Missing authorization" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;

    // Verify caller is admin using their JWT
    const callerClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
    });
    const {
      data: { user: caller },
    } = await callerClient.auth.getUser();
    if (!caller) {
      return new Response(JSON.stringify({ error: "Not authenticated" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Check caller is admin
    const { data: callerEmp } = await callerClient
      .from("employees")
      .select("role")
      .eq("auth_user_id", caller.id)
      .maybeSingle();

    if (!callerEmp || callerEmp.role !== "admin") {
      return new Response(
        JSON.stringify({ error: "Only admins can create employees" }),
        {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Parse request body
    const { name, email, department, role, password } = await req.json();

    if (!name || !email || !department || !role || !password) {
      return new Response(
        JSON.stringify({ error: "Missing required fields" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    if (password.length < 8) {
      return new Response(
        JSON.stringify({
          error: "Password must be at least 8 characters",
        }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Use service role to create auth user (sends confirmation email)
    const adminClient = createClient(supabaseUrl, serviceRoleKey);

    const { data: authData, error: authError } =
      await adminClient.auth.admin.createUser({
        email: email.toLowerCase(),
        password,
        email_confirm: true, // Admin-created accounts are auto-confirmed
        user_metadata: { name, department, role },
      });

    if (authError) {
      return new Response(JSON.stringify({ error: authError.message }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Generate avatar initials
    const initials = name
      .split(" ")
      .map((w: string) => w[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);

    // Create employee record
    const empId =
      "e" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const { data: empData, error: empError } = await adminClient
      .from("employees")
      .insert({
        id: empId,
        name,
        email: email.toLowerCase(),
        department,
        role,
        avatar: initials,
        auth_user_id: authData.user.id,
      })
      .select()
      .single();

    if (empError) {
      // Rollback: delete the auth user
      await adminClient.auth.admin.deleteUser(authData.user.id);
      return new Response(
        JSON.stringify({ error: "Failed to create employee: " + empError.message }),
        {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    return new Response(
      JSON.stringify({
        ok: true,
        employee: {
          id: empData.id,
          name: empData.name,
          email: empData.email,
          department: empData.department,
          role: empData.role,
          avatar: empData.avatar,
        },
      }),
      {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
