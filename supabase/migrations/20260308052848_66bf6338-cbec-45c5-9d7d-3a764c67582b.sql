-- Create storage buckets for report images and PO documents
INSERT INTO storage.buckets (id, name, public) VALUES ('report-images', 'report-images', true);
INSERT INTO storage.buckets (id, name, public) VALUES ('po-documents', 'po-documents', true);

-- RLS: authenticated users can upload to report-images
CREATE POLICY "Authenticated users can upload report images"
ON storage.objects FOR INSERT TO authenticated
WITH CHECK (bucket_id = 'report-images');

CREATE POLICY "Anyone can view report images"
ON storage.objects FOR SELECT TO authenticated
USING (bucket_id = 'report-images');

CREATE POLICY "Authenticated users can delete own report images"
ON storage.objects FOR DELETE TO authenticated
USING (bucket_id = 'report-images');

-- RLS: authenticated users can upload PO documents
CREATE POLICY "Authenticated users can upload po documents"
ON storage.objects FOR INSERT TO authenticated
WITH CHECK (bucket_id = 'po-documents');

CREATE POLICY "Anyone can view po documents"
ON storage.objects FOR SELECT TO authenticated
USING (bucket_id = 'po-documents');

CREATE POLICY "Authenticated users can delete own po documents"
ON storage.objects FOR DELETE TO authenticated
USING (bucket_id = 'po-documents');

-- Add image_url column to reports table
ALTER TABLE public.reports ADD COLUMN IF NOT EXISTS image_url text;

-- Add po_document_url column to projects table  
ALTER TABLE public.projects ADD COLUMN IF NOT EXISTS po_document_url text;