
-- Create employees table
CREATE TABLE public.employees (
  id TEXT PRIMARY KEY,
  auth_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL UNIQUE,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  department TEXT NOT NULL,
  avatar TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL CHECK (role IN ('admin', 'tl', 'employee')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create projects table
CREATE TABLE public.projects (
  id TEXT PRIMARY KEY DEFAULT ('p' || substr(gen_random_uuid()::text, 1, 8)),
  name TEXT NOT NULL,
  po_number TEXT,
  company_name TEXT,
  project_type TEXT,
  work_location TEXT,
  po_date DATE,
  total_work_qty NUMERIC DEFAULT 0,
  unit_type TEXT,
  work_type TEXT,
  department TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'completed')),
  start_date DATE,
  end_date DATE,
  description TEXT,
  assigned_employees TEXT[] DEFAULT '{}',
  last_updated_at TIMESTAMPTZ DEFAULT now(),
  last_update_type TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create reports table
CREATE TABLE public.reports (
  id TEXT PRIMARY KEY DEFAULT ('r' || substr(gen_random_uuid()::text, 1, 8)),
  employee_id TEXT NOT NULL REFERENCES public.employees(id),
  project_id TEXT NOT NULL REFERENCES public.projects(id),
  date DATE NOT NULL,
  hours NUMERIC NOT NULL,
  manpower_count INTEGER DEFAULT 1,
  work_qty_done NUMERIC DEFAULT 0,
  work_details TEXT,
  raw_description TEXT,
  ai_summary TEXT,
  tasks_completed TEXT[] DEFAULT '{}',
  issues_faced TEXT[] DEFAULT '{}',
  location_lat NUMERIC,
  location_lng NUMERIC,
  location_address TEXT,
  image_uploaded BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create announcements table
CREATE TABLE public.announcements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_id TEXT REFERENCES public.employees(id),
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  department TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.employees ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.announcements ENABLE ROW LEVEL SECURITY;

-- RLS Policies: authenticated users can read all data
CREATE POLICY "Authenticated users can read employees" ON public.employees FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated users can read projects" ON public.projects FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated users can read reports" ON public.reports FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated users can read announcements" ON public.announcements FOR SELECT TO authenticated USING (true);

-- Insert policies
CREATE POLICY "Authenticated users can insert reports" ON public.reports FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated users can insert projects" ON public.projects FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated users can insert announcements" ON public.announcements FOR INSERT TO authenticated WITH CHECK (true);

-- Update policies
CREATE POLICY "Authenticated users can update projects" ON public.projects FOR UPDATE TO authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Authenticated users can update employees" ON public.employees FOR UPDATE TO authenticated USING (true) WITH CHECK (true);

-- Delete policies
CREATE POLICY "Authenticated users can delete projects" ON public.projects FOR DELETE TO authenticated USING (true);
