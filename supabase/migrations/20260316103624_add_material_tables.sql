
-- Create materials table
CREATE TABLE IF NOT EXISTS public.materials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id text NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  item_name text NOT NULL,
  model_number text,
  supplied_qty integer NOT NULL DEFAULT 0,
  unit text NOT NULL DEFAULT 'Nos',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Create material_usage table
CREATE TABLE IF NOT EXISTS public.material_usage (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id text NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  item_id uuid NOT NULL REFERENCES public.materials(id) ON DELETE CASCADE,
  consumed_qty integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.materials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.material_usage ENABLE ROW LEVEL SECURITY;

-- RLS policies for materials
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Authenticated users can read materials') THEN
        CREATE POLICY "Authenticated users can read materials" ON public.materials FOR SELECT TO authenticated USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Authenticated users can insert materials') THEN
        CREATE POLICY "Authenticated users can insert materials" ON public.materials FOR INSERT TO authenticated WITH CHECK (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Authenticated users can update materials') THEN
        CREATE POLICY "Authenticated users can update materials" ON public.materials FOR UPDATE TO authenticated USING (true) WITH CHECK (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Authenticated users can delete materials') THEN
        CREATE POLICY "Authenticated users can delete materials" ON public.materials FOR DELETE TO authenticated USING (true);
    END IF;
END $$;

-- RLS policies for material_usage
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Authenticated users can read material_usage') THEN
        CREATE POLICY "Authenticated users can read material_usage" ON public.material_usage FOR SELECT TO authenticated USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Authenticated users can insert material_usage') THEN
        CREATE POLICY "Authenticated users can insert material_usage" ON public.material_usage FOR INSERT TO authenticated WITH CHECK (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Authenticated users can update material_usage') THEN
        CREATE POLICY "Authenticated users can update material_usage" ON public.material_usage FOR UPDATE TO authenticated USING (true) WITH CHECK (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Authenticated users can delete material_usage') THEN
        CREATE POLICY "Authenticated users can delete material_usage" ON public.material_usage FOR DELETE TO authenticated USING (true);
    END IF;
END $$;

-- Data Migration from project_items and reports to avoid data loss
INSERT INTO public.materials (id, project_id, item_name, supplied_qty, unit, created_at)
SELECT id, project_id, description, quantity, unit, created_at 
FROM public.project_items
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.material_usage (project_id, item_id, consumed_qty, created_at)
SELECT project_id, project_item_id, work_qty_done, created_at 
FROM public.reports 
WHERE project_item_id IS NOT NULL
ON CONFLICT DO NOTHING;

-- Create aggregation view for WCR as requested
CREATE OR REPLACE VIEW public.material_consumption_report AS
SELECT 
    m.id AS material_id,
    m.project_id,
    m.item_name,
    m.model_number,
    m.supplied_qty,
    m.unit,
    COALESCE(SUM(u.consumed_qty), 0) AS total_consumed,
    m.supplied_qty - COALESCE(SUM(u.consumed_qty), 0) AS balance_qty
FROM public.materials m
LEFT JOIN public.material_usage u ON m.id = u.item_id
GROUP BY 
    m.id,
    m.project_id,
    m.item_name,
    m.model_number,
    m.supplied_qty,
    m.unit;
