import os
from supabase import create_client, Client

class DatabaseService:
    def __init__(self):
        self.url = os.getenv("SUPABASE_URL")
        self.key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") # Use Service Role for backend admin tasks
        
        if not self.url or not self.key:
            print("WARNING: Supabase credentials missing in .env")
            self.client = None
        else:
            try:
                self.client = create_client(self.url, self.key)
                print("Supabase Client Initialized.")
            except Exception as e:
                print(f"Failed to initialize Supabase client: {e}")
                self.client = None

    # --- Auth Methods ---

    def signup(self, email, password, full_name):
        if not self.client:
            return {"error": "Database unavailable"}
        
        try:
            # 1. Create User in Auth
            # Some versions use a dict, others named args. Dict is safer for current supabase-py.
            res = self.client.auth.sign_up({
                "email": email,
                "password": password
            })
            
            if res.user:
                # 2. Add to profiles table
                try:
                    self.client.table('profiles').insert({
                        "id": res.user.id,
                        "full_name": full_name
                    }).execute()
                except Exception as table_e:
                    print(f"DEBUG: Profile table insert failed (check if table exists): {table_e}")
                    # We still return success for auth, but warn about profile
                
                return {"user": res.user, "session": res.session}
            
            print(f"DEBUG: Supabase Auth Signup failed: {res}")
            return {"error": "Signup failed"}
            
        except Exception as e:
            print(f"DEBUG: Supabase Exception during Signup: {str(e)}")
            return {"error": str(e)}

    def login(self, email, password):
        if not self.client:
            return {"error": "Database unavailable"}
        
        try:
            res = self.client.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            return {"user": res.user, "session": res.session}
        except Exception as e:
            return {"error": str(e)}

    # --- Scan Methods ---

    def log_scan(self, user_id, scan_type, input_data, result, confidence, reason):
        if not self.client:
            return
        
        try:
            data = {
                "user_id": user_id,
                "scan_type": scan_type,
                "input_data": str(input_data)[:500], # Trucate if too long
                "result": result,
                "confidence": float(confidence),
                "reason": reason
            }
            print(f"DEBUG: Logging scan to DB - Type: {scan_type}, User: {user_id}")
            self.client.table('scans').insert(data).execute()
        except Exception as e:
            print(f"Failed to log scan to Supabase: {e}")

    def get_user_scans(self, user_id):
        if not self.client:
            return []
        
        try:
            res = self.client.table('scans').select("*").eq('user_id', user_id).order('created_at', desc=True).limit(50).execute()
            return res.data
        except Exception as e:
            print(f"Failed to fetch scans: {e}")
            return []

    def get_dashboard_stats(self, user_id):
        if not self.client:
            return {}
            
        try:
            # Get user scans for stats Calculation
            res = self.client.table('scans').select("scan_type, result").eq('user_id', user_id).execute()
            scans = res.data
            
            total = len(scans)
            threats = 0
            safe = 0
            
            type_counts = {}
            # Initialize common types for cleaner charts
            for t in ['URL', 'Email', 'SMS', 'File', 'Web', 'QR', 'Domain']:
                type_counts[t] = 0

            threat_counts = {"Malicious": 0, "Safe": 0}
            
            for s in scans:
                stype = s.get('scan_type')
                res_str = (s.get('result') or '').lower()
                
                if stype in type_counts:
                    type_counts[stype] += 1
                else:
                    type_counts[stype] = 1
                
                is_threat = any(x in res_str for x in ['malware', 'suspicious', 'phishing', 'scam', 'vulnerable', 'threat'])
                # Also check for result being non-safe labels from specific models
                if is_threat:
                    threats += 1
                    threat_counts["Malicious"] += 1
                else:
                    safe += 1
                    threat_counts["Safe"] += 1
            
            # Get recent scans for the "Recent Scans" card
            recent_res = self.client.table('scans').select("*").eq('user_id', user_id).order('created_at', desc=True).limit(5).execute()
            recent_scans = recent_res.data
            
            print(f"DEBUG: Dashboard Stats for {user_id}: Found {total} total scans, {len(recent_scans)} recent")
            
            return {
                "total_scans": total,
                "threats_detected": threats,
                "safe_results": safe,
                "detection_rate": round((threats / total * 100), 1) if total > 0 else 0,
                "type_breakdown": type_counts,
                "threat_breakdown": threat_counts,
                "recent_scans": recent_scans
            }
        except Exception as e:
            print(f"Failed to fetch dashboard stats: {e}")
            return {}

