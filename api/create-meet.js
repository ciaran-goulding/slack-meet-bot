/**
 * GOOGLE MEET SLACK BOT
 * ---------------------
 * A serverless function hosted on Vercel that handles Slash Commands (/googlemeet).
 *
 * FEATURES:
 * 1. Security: Verifies Slack signatures to prevent hack attempts.
 * 2. Privacy: Generates unique "Lookup" links so rooms never collide.
 * 3. Audit: Logs meeting creation to a specific Google Calendar.
 * 4. UX: Fetches real user names for clean meeting titles.
 */

import { google } from 'googleapis';
import crypto from 'crypto';

/**
 * CONFIGURATION: Disable Body Parser
 * Vercel tries to parse JSON automatically. We must disable this because
 * Slack's security verification requires the raw, un-touched request body string.
 */
export const config = {
  api: { bodyParser: false },
};

// --- HELPER: Read Raw Request Body ---
async function getRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString();
}

// --- HELPER: Verify Slack Security Signature ---
function verifyRequest(headers, rawBody) {
  const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
  const timestamp = headers['x-slack-request-timestamp'];
  const slackSignature = headers['x-slack-signature'];

  // 1. Check for missing headers
  if (!timestamp || !slackSignature) throw new Error('Missing headers');
  
  // 2. Replay Attack Protection: Reject requests older than 5 minutes
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
  if (timestamp < fiveMinutesAgo) throw new Error('Timestamp too old');

  // 3. Re-create the hash locally
  const baseString = `v0:${timestamp}:${rawBody}`;
  const hmac = crypto.createHmac('sha256', slackSigningSecret);
  hmac.update(baseString);
  const mySignature = `v0=${hmac.digest('hex')}`;

  // 4. Compare our hash with Slack's hash (Constant-time comparison for security)
  if (!crypto.timingSafeEqual(Buffer.from(mySignature), Buffer.from(slackSignature))) {
    throw new Error('Verification failed');
  }
}

// --- HELPER: Fetch User's Real Name ---
// Slack sends us a User ID (U123) or Username (2387). We want the Real Name (Ciaran).
async function getSlackName(userId) {
  const token = process.env.SLACK_BOT_TOKEN;
  if (!token) return null;

  try {
    const params = new URLSearchParams({ user: userId });
    const response = await fetch(`https://slack.com/api/users.info?${params}`, {
      method: 'GET',
      headers: { 
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const data = await response.json();
    if (data.ok && data.user) {
      return data.user.profile.real_name;
    }
  } catch (error) {
    console.error("Slack Lookup Error:", error.message);
  }
  return null;
}

// --- CORE LOGIC: Create Link & Log to Calendar ---
async function createGoogleMeet(text, userId, defaultHandle) {
  let rawTitle;
  let suffix = "";
  
  // 1. Determine Meeting Title
  if (text && text.trim().length > 0) {
    // If user typed a title (e.g. "/meet Project Sync"), use it exactly.
    rawTitle = text;
  } else {
    // If empty, fetch real name and append a random code for uniqueness.
    const realName = await getSlackName(userId);
    const displayName = realName || defaultHandle;
    
    // Random 4-digit code (e.g. 4821) prevents "Instant Meeting" collisions.
    const randomCode = Math.floor(1000 + Math.random() * 9000);
    rawTitle = `${displayName}'s meeting`; 
    suffix = `-${randomCode}`;
  }

  // 2. Sanitize Title for URL
  // Convert "Ciaran's Meeting!" -> "ciarans-meeting"
  const cleanSlug = rawTitle.toLowerCase()
    .replace(/['’]/g, '')       // Remove apostrophes
    .replace(/\s+/g, '-')       // Replace spaces with hyphens
    .replace(/[^a-z0-9-]/g, '') // Remove special characters
    .replace(/-+/g, '-');       // Cleanup double hyphens

  const meetLink = `https://meet.google.com/lookup/${cleanSlug}${suffix}`;
  
  // 3. Log to Google Calendar (Audit Trail)
  try {
    const calendarId = process.env.CALENDAR_ID;
    const clientEmail = process.env.GOOGLE_CLIENT_EMAIL;
    const encodedPrivateKey = process.env.GOOGLE_PRIVATE_KEY; 

    if (calendarId && clientEmail && encodedPrivateKey) {
      // Decode the Base64 key safe-storage
      let privateKey;
      try {
        privateKey = Buffer.from(encodedPrivateKey, 'base64').toString('utf8');
      } catch (e) {}

      if (privateKey) {
        // Fix newlines if they were escaped during copy/paste
        if (privateKey.includes('\\n')) {
          privateKey = privateKey.replace(/\\n/g, '\n');
        }

        // Authenticate as Service Account
        const auth = new google.auth.GoogleAuth({
          credentials: { client_email: clientEmail, private_key: privateKey },
          scopes: ['https://www.googleapis.com/auth/calendar.events'],
        });

        const client = await auth.getClient();
        const calendar = google.calendar({ version: 'v3', auth: client });

        // --- TIME SETTING: 30 MINUTES ---
        const eventStartTime = new Date();
        const eventEndTime = new Date();
        // Updated to 30 minutes as requested
        eventEndTime.setMinutes(eventStartTime.getMinutes() + 30);

        // Create the event
        await calendar.events.insert({
          calendarId: calendarId,
          resource: {
            summary: rawTitle, 
            description: `Meeting created by Slack.\nJoin: ${meetLink}`,
            location: meetLink,
            start: { dateTime: eventStartTime.toISOString(), timeZone: 'UTC' },
            end: { dateTime: eventEndTime.toISOString(), timeZone: 'UTC' },
          },
        });
      }
    }
  } catch (error) {
    // Log error but don't crash; the user still gets their link.
    console.error("Calendar Log Error:", error);
  }
  
  return meetLink;
}

// --- MAIN HANDLER ---
export default async (request, response) => {
  if (request.method !== 'POST') return response.status(405).send('Method Not Allowed');

  try {
    const rawBody = await getRawBody(request);
    verifyRequest(request.headers, rawBody);

    const params = new URLSearchParams(rawBody);

    // --- INTERACTIVITY FIX ---
    // If Slack sends a "payload" (user clicked a button), we respond 200 OK
    // immediately to prevent the "Warning Triangle" icon.
    if (params.get('payload')) {
      return response.status(200).send('');
    }

    // Parse slash command params
    const text = params.get('text');
    const userId = params.get('user_id');
    const handle = params.get('user_name');

    // Run Logic
    const meetLink = await createGoogleMeet(text, userId, handle);

    // Return Slack Block Kit UI
    return response.status(200).json({
      response_type: 'in_channel', // Visible to everyone
      blocks: [
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: "Click below to join:"
          }
        },
        {
          type: "actions",
          elements: [
            {
              type: "button",
              text: {
                type: "plain_text",
                text: "Join Meeting",
                emoji: true
              },
              url: meetLink,
              style: "primary", // Green button
              action_id: "join_button" // Required for interactivity check
            }
          ]
        }
      ]
    });

  } catch (error) {
    console.error('Handler Error:', error);
    return response.status(200).json({
      response_type: 'ephemeral', // Only visible to the user
      text: `⚠️ Error: ${error.message}`,
    });
  }
};