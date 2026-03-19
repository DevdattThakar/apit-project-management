export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.4"
  }
  public: {
    Tables: {
      announcements: {
        Row: {
          created_at: string
          department: string | null
          id: string
          message: string
          sender_id: string | null
          title: string
        }
        Insert: {
          created_at?: string
          department?: string | null
          id?: string
          message: string
          sender_id?: string | null
          title: string
        }
        Update: {
          created_at?: string
          department?: string | null
          id?: string
          message?: string
          sender_id?: string | null
          title?: string
        }
        Relationships: [
          {
            foreignKeyName: "announcements_sender_id_fkey"
            columns: ["sender_id"]
            isOneToOne: false
            referencedRelation: "employees"
            referencedColumns: ["id"]
          },
        ]
      }
      employees: {
        Row: {
          auth_user_id: string | null
          avatar: string
          created_at: string
          department: string
          email: string
          id: string
          name: string
          role: string
        }
        Insert: {
          auth_user_id?: string | null
          avatar?: string
          created_at?: string
          department: string
          email: string
          id: string
          name: string
          role: string
        }
        Update: {
          auth_user_id?: string | null
          avatar?: string
          created_at?: string
          department?: string
          email?: string
          id?: string
          name?: string
          role?: string
        }
        Relationships: []
      }
      project_items: {
        Row: {
          category: string | null
          created_at: string
          description: string
          id: string
          project_id: string
          quantity: number
          rate: string | null
          unit: string
          work_type: string | null
        }
        Insert: {
          category?: string | null
          created_at?: string
          description: string
          id?: string
          project_id: string
          quantity?: number
          rate?: string | null
          unit?: string
          work_type?: string | null
        }
        Update: {
          category?: string | null
          created_at?: string
          description?: string
          id?: string
          project_id?: string
          quantity?: number
          rate?: string | null
          unit?: string
          work_type?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "project_items_project_id_fkey"
            columns: ["project_id"]
            isOneToOne: false
            referencedRelation: "projects"
            referencedColumns: ["id"]
          },
        ]
      }
      projects: {
        Row: {
          assigned_employees: string[] | null
          company_name: string | null
          created_at: string
          department: string | null
          description: string | null
          end_date: string | null
          id: string
          last_update_type: string | null
          last_updated_at: string | null
          name: string
          po_date: string | null
          po_document_url: string | null
          po_documents: Json | null
          po_number: string | null
          project_type: string | null
          start_date: string | null
          status: string
          total_work_qty: number | null
          unit_type: string | null
          work_location: string | null
          work_type: string | null
        }
        Insert: {
          assigned_employees?: string[] | null
          company_name?: string | null
          created_at?: string
          department?: string | null
          description?: string | null
          end_date?: string | null
          id?: string
          last_update_type?: string | null
          last_updated_at?: string | null
          name: string
          po_date?: string | null
          po_document_url?: string | null
          po_documents?: Json | null
          po_number?: string | null
          project_type?: string | null
          start_date?: string | null
          status?: string
          total_work_qty?: number | null
          unit_type?: string | null
          work_location?: string | null
          work_type?: string | null
        }
        Update: {
          assigned_employees?: string[] | null
          company_name?: string | null
          created_at?: string
          department?: string | null
          description?: string | null
          end_date?: string | null
          id?: string
          last_update_type?: string | null
          last_updated_at?: string | null
          name?: string
          po_date?: string | null
          po_document_url?: string | null
          po_documents?: Json | null
          po_number?: string | null
          project_type?: string | null
          start_date?: string | null
          status?: string
          total_work_qty?: number | null
          unit_type?: string | null
          work_location?: string | null
          work_type?: string | null
        }
        Relationships: []
      }
      reports: {
        Row: {
          ai_summary: string | null
          created_at: string
          date: string
          employee_id: string
          hours: number
          id: string
          image_uploaded: boolean | null
          image_url: string | null
          issues_faced: string[] | null
          location_address: string | null
          location_lat: number | null
          location_lng: number | null
          manpower_count: number | null
          project_id: string
          project_item_id: string | null
          raw_description: string | null
          tasks_completed: string[] | null
          work_details: string | null
          work_qty_done: number | null
        }
        Insert: {
          ai_summary?: string | null
          created_at?: string
          date: string
          employee_id: string
          hours: number
          id?: string
          image_uploaded?: boolean | null
          image_url?: string | null
          issues_faced?: string[] | null
          location_address?: string | null
          location_lat?: number | null
          location_lng?: number | null
          manpower_count?: number | null
          project_id: string
          project_item_id?: string | null
          raw_description?: string | null
          tasks_completed?: string[] | null
          work_details?: string | null
          work_qty_done?: number | null
        }
        Update: {
          ai_summary?: string | null
          created_at?: string
          date?: string
          employee_id?: string
          hours?: number
          id?: string
          image_uploaded?: boolean | null
          image_url?: string | null
          issues_faced?: string[] | null
          location_address?: string | null
          location_lat?: number | null
          location_lng?: number | null
          manpower_count?: number | null
          project_id?: string
          project_item_id?: string | null
          raw_description?: string | null
          tasks_completed?: string[] | null
          work_details?: string | null
          work_qty_done?: number | null
        }
        Relationships: [
          {
            foreignKeyName: "reports_employee_id_fkey"
            columns: ["employee_id"]
            isOneToOne: false
            referencedRelation: "employees"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "reports_project_id_fkey"
            columns: ["project_id"]
            isOneToOne: false
            referencedRelation: "projects"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "reports_project_item_id_fkey"
            columns: ["project_item_id"]
            isOneToOne: false
            referencedRelation: "project_items"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      [_ in never]: never
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {},
  },
} as const
