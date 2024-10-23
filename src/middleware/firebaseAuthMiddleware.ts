import { NextRequest, NextResponse } from 'next/server';
import { getAuth } from 'firebase-admin/auth';
import { initializeApp, getApps, cert } from 'firebase-admin/app';
import { corsHeaders } from '@/lib/utils';

// Initialize Firebase Admin SDK if it hasn't been initialized yet
if (!getApps().length) {
    initializeApp({
        credential: cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY || '{}')),
    });
}

export async function firebaseAuthMiddleware(req: NextRequest) {
    const authHeader = req.headers.get('Authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return new NextResponse(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: {
                'Content-Type': 'application/json',
                ...corsHeaders
            }
        });
    }

    const token = authHeader.split('Bearer ')[1];

    try {
        await getAuth().verifyIdToken(token);
        // If verification succeeds, continue to the API route
        return null;
    } catch (error) {
        console.error('Error verifying Firebase token:', error);
        return new NextResponse(JSON.stringify({ error: 'Invalid token' }), {
            status: 401,
            headers: {
                'Content-Type': 'application/json',
                ...corsHeaders
            }
        });
    }
}
