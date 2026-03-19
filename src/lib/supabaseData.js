import { supabase } from "@/integrations/supabase/client";

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL;

// ── Auth ──
export async function supabaseLogin(email, password) {
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return { ok: false, error: error.message };
  
  // Fetch employee record linked to this auth user
  const { data: emp, error: empErr } = await supabase
    .from("employees")
    .select("*")
    .eq("auth_user_id", data.user.id)
    .maybeSingle();
  
  if (empErr || !emp) {
    // Fallback: try matching by email
    const { data: empByEmail } = await supabase
      .from("employees")
      .select("*")
      .eq("email", email.toLowerCase())
      .maybeSingle();
    
    if (empByEmail) {
      // Link the auth user
      await supabase.from("employees").update({ auth_user_id: data.user.id }).eq("id", empByEmail.id);
      return { ok: true, user: mapEmployee(empByEmail) };
    }
    return { ok: false, error: "No employee record found for this account." };
  }
  
  return { ok: true, user: mapEmployee(emp) };
}

export async function supabaseLogout() {
  await supabase.auth.signOut();
}

export async function getSession() {
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return null;
  
  const { data: emp } = await supabase
    .from("employees")
    .select("*")
    .eq("auth_user_id", session.user.id)
    .maybeSingle();
  
  if (!emp) return null;
  return mapEmployee(emp);
}

function mapEmployee(emp) {
  return {
    id: emp.id,
    name: emp.name,
    email: emp.email,
    department: emp.department,
    avatar: emp.avatar,
    role: emp.role,
  };
}

// ── Project Items (BOQ/Materials) ──
export async function fetchProjectItems() {
  const { data, error } = await supabase
    .from("project_items")
    .select("id, project_id, item_name, supplied_qty, used_qty, unit, model_number, work_type, category, rate")
    .order("created_at");
  if (error) { console.error("fetchProjectItems:", error); return []; }
  return data.map(i => ({
    id: i.id,
    projectId: i.project_id,
    description: i.item_name,
    quantity: Number(i.supplied_qty) || 0,
    usedQty: Number(i.used_qty) || 0,
    unit: i.unit,
    model: i.model_number,
    workType: i.work_type,
    category: i.category,
    rate: i.rate,
  }));
}

export async function insertProjectItems(projectId, items) {
  if (!items || items.length === 0) return [];
  const rows = items.map(i => ({
    project_id: projectId,
    item_name: i.description,
    supplied_qty: Math.round(Number(i.qty || i.quantity || 0)),
    unit: i.unit || "Nos",
    model_number: i.model || i.partNumber || null,
    work_type: i.workType || null,
    category: i.category || "Other",
    rate: i.rate || null,
    used_qty: 0,
  }));
  const { data, error } = await supabase.from("project_items").insert(rows).select();
  if (error) { console.error("insertProjectItems:", error); throw error; }
  return data;
}

export async function deleteProjectItems(projectId) {
  const { error } = await supabase.from("project_items").delete().eq("project_id", projectId);
  if (error) { console.error("deleteProjectItems:", error); throw error; }
}

// ── Data Fetching ──
export async function fetchEmployees() {
  const { data, error } = await supabase.from("employees").select("*").order("name");
  if (error) { console.error("fetchEmployees:", error); return []; }
  return data.map(mapEmployee);
}

export async function fetchProjects() {
  const { data, error } = await supabase.from("projects").select("*").order("created_at", { ascending: false });
  if (error) { console.error("fetchProjects:", error); return []; }
  return data.map(p => ({
    id: p.id,
    name: p.name,
    poNumber: p.po_number,
    companyName: p.company_name,
    projectType: p.project_type,
    workLocation: p.work_location,
    poDate: p.po_date,
    totalWorkQty: Math.round(Number(p.total_work_qty) || 0),
    unitType: p.unit_type,
    workType: p.work_type,
    department: p.department,
    status: p.status,
    startDate: p.start_date,
    endDate: p.end_date,
    description: p.description,
    assignedEmployees: p.assigned_employees || [],
    lastUpdatedAt: p.last_updated_at,
    lastUpdateType: p.last_update_type,
    poDocuments: p.po_documents || [],
  }));
}

export async function fetchReports() {
  const { data, error } = await supabase.from("reports").select("*").order("created_at", { ascending: false });
  if (error) { console.error("fetchReports:", error); return []; }
  return data.map(r => ({
    id: r.id,
    employeeId: r.employee_id,
    projectId: r.project_id,
    date: r.date,
    hours: Number(r.hours),
    manpowerCount: Number(r.manpower_count) || 1,
    workQtyDone: Math.round(Number(r.work_qty_done) || 0),
    projectItemId: r.project_item_id || null,
    workDetails: r.work_details,
    rawDescription: r.raw_description,
    aiSummary: r.ai_summary,
    tasksCompleted: r.tasks_completed || [],
    issuesFaced: r.issues_faced || [],
    location: {
      lat: Number(r.location_lat) || 0,
      lng: Number(r.location_lng) || 0,
      address: r.location_address || "",
    },
    imageUploaded: r.image_uploaded,
  }));
}

export async function fetchAnnouncements() {
  const { data, error } = await supabase.from("announcements").select("*").order("created_at", { ascending: false });
  if (error) { console.error("fetchAnnouncements:", error); return []; }
  return data.map(a => {
    let title = a.title;
    let priority = "normal";
    let recipientIds = [];
    let senderName = "Team Lead";
    
    // Attempt to parse metadata from title
    if (a.title && (a.title.startsWith("{") || a.title.startsWith("["))) {
      try {
        const meta = JSON.parse(a.title);
        if (meta && typeof meta === "object") {
          title = meta.t || a.title;
          priority = meta.p || "normal";
          recipientIds = meta.r || [];
          senderName = meta.n || "Team Lead";
        }
      } catch (e) {
        // Fallback to raw title
      }
    }

    return {
      id: a.id,
      fromId: a.sender_id,
      from: senderName, 
      message: a.message,
      title: title,
      priority: priority,
      recipientIds: recipientIds,
      department: a.department,
      fromDept: a.department,
      sentAt: a.created_at,
      sentAtLabel: new Date(a.created_at).toLocaleString("en-GB", {
        day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit"
      }),
    };
  });
}

// ── File Storage ──
export async function uploadReportImage(file, reportId) {
  const ext = file.name.split('.').pop();
  const path = `${reportId}/image.${ext}`;
  const { error } = await supabase.storage.from("report-images").upload(path, file, { upsert: true });
  if (error) { console.error("uploadReportImage:", error); throw error; }
  const { data: { publicUrl } } = supabase.storage.from("report-images").getPublicUrl(path);
  return publicUrl;
}

export async function uploadPODocument(file, projectId) {
  const ext = file.name.split('.').pop();
  const path = `${projectId}/po-doc.${ext}`;
  const { error } = await supabase.storage.from("po-documents").upload(path, file, { upsert: true });
  if (error) { console.error("uploadPODocument:", error); throw error; }
  const { data: { publicUrl } } = supabase.storage.from("po-documents").getPublicUrl(path);
  return publicUrl;
}

// ── Data Mutations ──
export async function insertReport(report) {
  // Insert main report
  const { data, error } = await supabase.from("reports").insert({
    id: report.id,
    employee_id: report.employeeId,
    project_id: report.projectId,
    date: report.date,
    hours: report.hours,
    manpower_count: report.manpowerCount,
    work_qty_done: report.workQtyDone,
    work_details: report.workDetails,
    raw_description: report.rawDescription,
    ai_summary: report.aiSummary,
    tasks_completed: report.tasksCompleted,
    issues_faced: report.issuesFaced,
    location_lat: report.location?.lat,
    location_lng: report.location?.lng,
    location_address: report.location?.address,
    image_uploaded: report.imageUploaded,
    image_url: report.imageUrl || null,
    project_item_id: report.projectItemId || null,
  }).select().single();
  
  if (error) { console.error("insertReport:", error); throw error; }

  // Denormalize usage into project_items table
  if (report.projectItemId && report.workQtyDone > 0) {
    const { data: item } = await supabase
      .from("project_items")
      .select("used_qty")
      .eq("id", report.projectItemId)
      .maybeSingle();
    
    if (item) {
      await supabase
        .from("project_items")
        .update({ used_qty: (Number(item.used_qty) || 0) + Number(report.workQtyDone) })
        .eq("id", report.projectItemId);
    }
  }

  return data;
}

export async function insertProject(project) {
  const { data, error } = await supabase.from("projects").insert({
    id: project.id,
    name: project.name,
    po_number: project.poNumber,
    company_name: project.companyName,
    project_type: project.projectType,
    work_location: project.workLocation,
    po_date: project.poDate || null,
    total_work_qty: project.totalWorkQty,
    unit_type: project.unitType,
    work_type: project.workType,
    department: project.department,
    status: project.status || "active",
    start_date: project.startDate || null,
    end_date: project.endDate || null,
    description: project.description,
    assigned_employees: project.assignedEmployees || [],
    last_updated_at: project.lastUpdatedAt || new Date().toISOString(),
    last_update_type: project.lastUpdateType || "Project created",
    po_documents: project.poDocuments || [],
  }).select().single();
  if (error) { console.error("insertProject:", error); throw error; }
  return data;
}

export async function updateProject(project) {
  const { error } = await supabase.from("projects").update({
    name: project.name,
    po_number: project.poNumber,
    company_name: project.companyName,
    project_type: project.projectType,
    work_location: project.workLocation,
    po_date: project.poDate || null,
    total_work_qty: project.totalWorkQty,
    unit_type: project.unitType,
    work_type: project.workType,
    department: project.department,
    status: project.status,
    start_date: project.startDate || null,
    end_date: project.endDate || null,
    description: project.description,
    assigned_employees: project.assignedEmployees || [],
    last_updated_at: project.lastUpdatedAt || new Date().toISOString(),
    last_update_type: project.lastUpdateType || "Project edited",
    po_documents: project.poDocuments || [],
  }).eq("id", project.id);
  if (error) { console.error("updateProject:", error); throw error; }
}

export async function updateProjectStatus(id, status, updatedBy) {
  const { error } = await supabase.from("projects").update({
    status,
    last_updated_at: new Date().toISOString(),
    last_update_type: "Status → " + status,
  }).eq("id", id);
  if (error) { console.error("updateProjectStatus:", error); throw error; }
}

export async function insertAnnouncement(announcement) {
  // We encode priority and recipientIds into the title as JSON
  // since the current schema only has title, message, dept, sender_id
  const dbPayload = {
    sender_id: announcement.fromId || announcement.senderId,
    message: announcement.message || "",
    department: announcement.fromDept || announcement.department,
    title: JSON.stringify({
      t: announcement.title || "Announcement",
      p: announcement.priority || "normal",
      r: announcement.recipientIds || [],
      n: announcement.from || "Team Lead"
    })
  };

  const { data, error } = await supabase.from("announcements").insert(dbPayload).select().single();
  if (error) { console.error("insertAnnouncement:", error); throw error; }
  return data;
}

// ── Admin: Create Employee ──
export async function createEmployee({ name, email, department, role, password }) {
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) throw new Error("Not authenticated");

  const res = await fetch(`${SUPABASE_URL}/functions/v1/create-employee`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${session.access_token}`,
    },
    body: JSON.stringify({ name, email, department, role, password }),
  });

  const json = await res.json();
  if (!res.ok || json.error) throw new Error(json.error || "Failed to create employee");
  return json.employee;
}

// ── Material Consumption (WCR items) ──
export async function fetchMaterialConsumption(projectId) {
  const { data, error } = await supabase
    .from("project_items")
    .select("item_name, model_number, supplied_qty, used_qty, unit, project_id")
    .eq("project_id", projectId);
  
  if (error) { console.error("fetchMaterialConsumption:", error); return []; }
  return data.map(m => ({
    itemName: m.item_name,
    modelNumber: m.model_number || "-",
    suppliedQty: m.supplied_qty,
    consumedQty: m.used_qty,
    balanceQty: m.supplied_qty - m.used_qty,
    unit: m.unit,
  }));
}
