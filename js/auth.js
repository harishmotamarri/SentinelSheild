import { supabaseClient } from './supabase.js';

export const auth = {
    async signIn(email, password) {
        return await supabaseClient.auth.signInWithPassword({
            email,
            password,
        });
    },

    async signUp(email, password, fullName) {
        return await supabaseClient.auth.signUp({
            email,
            password,
            options: {
                data: {
                    full_name: fullName,
                }
            }
        });
    },

    async signOut() {
        return await supabaseClient.auth.signOut();
    },

    async getUser() {
        const { data: { user } } = await supabaseClient.auth.getUser();
        return user;
    },

    async isAdmin() {
        const user = await this.getUser();
        if (!user) return false;
        const { data, error } = await supabaseClient
            .from('admins')
            .select('id')
            .eq('id', user.id)
            .single();
        return !!data && !error;
    },

    async checkAuth(redirectIfNotAuth = true, requireAdmin = false) {
        const user = await this.getUser();
        if (!user && redirectIfNotAuth) {
            window.location.href = '/login.html';
            return null;
        }
        if (requireAdmin) {
            const admin = await this.isAdmin();
            if (!admin && redirectIfNotAuth) {
                window.location.href = '/dashboard.html';
                return null;
            }
        }
        return user;
    }
};
