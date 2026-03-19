
-- Create project_items table for multiple BOQ items per project
CREATE TABLE public.project_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id text NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  description text NOT NULL,
  quantity integer NOT NULL DEFAULT 0,
  unit text NOT NULL DEFAULT 'Nos',
  work_type text,
  category text DEFAULT 'Other',
  rate text,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.project_items ENABLE ROW LEVEL SECURITY;

-- RLS policies for project_items
CREATE POLICY "Authenticated users can read project_items" ON public.project_items
  FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can insert project_items" ON public.project_items
  FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Authenticated users can update project_items" ON public.project_items
  FOR UPDATE TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "Authenticated users can delete project_items" ON public.project_items
  FOR DELETE TO authenticated USING (true);

-- Add project_item_id to reports table
ALTER TABLE public.reports ADD COLUMN project_item_id uuid REFERENCES public.project_items(id);

-- Change work_qty_done to integer
ALTER TABLE public.reports ALTER COLUMN work_qty_done TYPE integer USING COALESCE(ROUND(work_qty_done)::integer, 0);

-- Change total_work_qty to integer  
ALTER TABLE public.projects ALTER COLUMN total_work_qty TYPE integer USING COALESCE(ROUND(total_work_qty)::integer, 0);

-- Change manpower_count default
ALTER TABLE public.reports ALTER COLUMN manpower_count SET DEFAULT 1;
