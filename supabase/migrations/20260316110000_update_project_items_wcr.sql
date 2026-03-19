
-- Rename columns in project_items
ALTER TABLE public.project_items RENAME COLUMN description TO item_name;
ALTER TABLE public.project_items RENAME COLUMN quantity TO supplied_qty;

-- Add new columns
ALTER TABLE public.project_items ADD COLUMN IF NOT EXISTS model_number text;
ALTER TABLE public.project_items ADD COLUMN IF NOT EXISTS used_qty integer NOT NULL DEFAULT 0;

-- Update used_qty from existing reports
UPDATE public.project_items
SET used_qty = (
    SELECT COALESCE(SUM(work_qty_done), 0)
    FROM public.reports
    WHERE public.reports.project_item_id = public.project_items.id
);
