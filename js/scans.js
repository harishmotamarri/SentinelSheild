import { supabaseClient } from './supabase.js';
import { auth } from './auth.js';

export const scans = {
    async createScan(scanType, inputValue, fileData = null) {
        const user = await auth.getUser();
        if (!user) throw new Error('You must be logged in to perform scans');

        const functionName = `scan-${scanType}`;

        const { data, error } = await supabaseClient.functions.invoke(functionName, {
            body: { inputValue, fileData },
        });

        if (error) {
            console.error('Edge function error:', error);
            throw new Error(error.message || 'Failed to perform scan');
        }

        if (data.error) {
            throw new Error(data.error);
        }

        // Save scan to database
        const { error: insertError } = await supabaseClient
            .from('scans')
            .insert({
                user_id: user.id,
                scan_type: scanType,
                input_value: inputValue.substring(0, 1000),
                classification: data.classification,
                confidence_score: data.confidence_score,
                risk_level: data.risk_level,
                analysis_details: data.analysis_details,
            });

        if (insertError) {
            console.error('Insert error:', insertError);
            throw new Error('Failed to save scan result');
        }

        return data;
    }
};
