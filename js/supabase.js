const SUPABASE_URL = "https://bfcuwrbazynidkfvfipo.supabase.co";
const SUPABASE_PUBLISHABLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJmY3V3cmJhenluaWRrZnZmaXBvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjkwMjQ1OTUsImV4cCI6MjA4NDYwMDU5NX0.nFZVWWOrxIQEcB1UE-XlKbAViLQVDH-CZD_fyBxKVLM";

// Initialize Supabase
const { createClient } = supabase;
export const supabaseClient = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
    auth: {
        storage: localStorage,
        persistSession: true,
        autoRefreshToken: true,
    }
});
