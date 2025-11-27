/**
 * GOOGLE MEET SLACK BOT (Serverless Function)
 * -------------------------------------------
 * This function handles the /googlemeet slash command from Slack.
 *
 * WORKFLOW:
 * 1. Verifies the request signature to ensure it came from Slack.
 * 2. Determines a meeting title (User input OR "User's meeting" + random ID).
 * 3. Generates a unique "Lookup Link" (meet.google.com/lookup/...).
 * 4. Logs the meeting to a specific Google Calendar for auditing.
 * 5. Returns a rich UI card to the Slack channel.
 */

import { google } from 'googleapis';
import crypto from 'crypto';

/**
 * CONFIGURATION
 * -------------
 * Vercel automatically parses JSON bodies. We MUST disable this.
 * Slack's security signature is calculated based on the raw, unparsed text body.
 * If Vercel parses it first, the signature check will fail.
 */
export const config = {
  api: { bodyParser: false },
};

/**
 * HELPER: Get Raw Body
 * Reads the incoming data stream and converts it to a single string.
 */
async function getRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString();
}

/**
 * HELPER: Verify Slack Request
 * ----------------------------
 * Security checkpoint. Rejects requests that don't match Slack's signature.
 *
 * @param {object} headers - Request headers
 * @param {string} rawBody - The raw text body of the request
 */
function verifyRequest(headers, rawBody) {
  const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
  const timestamp = headers['x-slack-request-timestamp'];
  const slackSignature = headers['x-slack-signature'];

  // 1. Ensure headers exist
  if (!timestamp || !slackSignature) throw new Error('Missing headers');
  
  // 2. Prevent Replay Attacks: Reject requests older than 5 minutes
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
  if (timestamp < fiveMinutesAgo) throw new Error('Timestamp too old');

  // 3. Construct the signature string: v0:[Timestamp]:[Body]
  const baseString = `v0:${timestamp}:${rawBody}`;
  
  // 4. Hash it using HMAC-SHA256 and your Signing Secret
  const hmac = crypto.createHmac('sha256', slackSigningSecret);
  hmac.update(baseString);
  const mySignature = `v0=${hmac.digest('hex')}`;

  // 5. Compare our hash with Slack's hash
  if (!crypto.timingSafeEqual(Buffer.from(mySignature), Buffer.from(slackSignature))) {
    throw new Error('Verification failed');
  }
}

/**
 * HELPER: Fetch Real Name from Slack
 * ----------------------------------
 * Slack provides a User ID (U123) or Username (2387). We want the Real Name (Ciaran).
 * We use the Slack Web API to look up the user profile.
 */
async function getSlackName(userId) {
  const token = process.env.SLACK_BOT_TOKEN;
  if (!token) return null;

  try {
    // Use native Node.js 'fetch' to call Slack API
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

/**
 * CORE LOGIC: Create and Log Meeting
 * ----------------------------------
 * Generates the link and logs it to Google Calendar.
 */
async function createGoogleMeet(text, userId, defaultHandle) {
  let rawTitle;
  let suffix = "";
  
  // --- 1. DETERMINE MEETING TITLE ---
  if (text && text.trim().length > 0) {
    // Scenario A: User typed a specific title (e.g., "Project Sync")
    // We use this title exactly as is.
    rawTitle = text;
  } else {
    // Scenario B: User typed nothing (Instant Meeting)
    // We fetch their real name and append a random code to ensure the room is unique.
    const realName = await getSlackName(userId);
    const displayName = realName || defaultHandle;
    
    // Random 4-digit code (1000-9999) to prevent ID collisions
    const randomCode = Math.floor(1000 + Math.random() * 9000);
    
    rawTitle = `${displayName}'s meeting`; 
    suffix = `-${randomCode}`;
  }

  // --- 2. SANITIZE URL ---
  // Convert title into a valid URL "slug" (lowercase, no spaces/symbols)
  const cleanSlug = rawTitle.toLowerCase()
    .replace(/['’]/g, '')       // Remove apostrophes ("Ciaran's" -> "ciarans")
    .replace(/\s+/g, '-')       // Replace spaces with hyphens
    .replace(/[^a-z0-9-]/g, '') // Remove anything that isn't a letter/number/hyphen
    .replace(/-+/g, '-');       // Collapse multiple hyphens into one

  // The "Lookup" link redirects to a secure room based on this unique ID
  const meetLink = `https://meet.google.com/lookup/${cleanSlug}${suffix}`;
  
  // --- 3. LOG TO GOOGLE CALENDAR ---
  try {
    const calendarId = process.env.CALENDAR_ID;
    const clientEmail = process.env.GOOGLE_CLIENT_EMAIL;
    const encodedPrivateKey = process.env.GOOGLE_PRIVATE_KEY; 

    // Only proceed if all credentials exist
    if (calendarId && clientEmail && encodedPrivateKey) {
      let privateKey;
      try {
        // Decode the Base64 key from Vercel environment variables
        privateKey = Buffer.from(encodedPrivateKey, 'base64').toString('utf8');
      } catch (e) {
        console.error("Key Decode Error:", e.message);
      }

      if (privateKey) {
        // Fix: Ensure newline characters (\n) are interpreted correctly by Google
        if (privateKey.includes('\\n')) {
          privateKey = privateKey.replace(/\\n/g, '\n');
        }

        // Authenticate as the Service Account (Robot)
        const auth = new google.auth.GoogleAuth({
          credentials: { client_email: clientEmail, private_key: privateKey },
          scopes: ['https://www.googleapis.com/auth/calendar.events'],
        });

        const client = await auth.getClient();
        const calendar = google.calendar({ version: 'v3', auth: client });

        // Set event duration (30 minute default - purely for calendar visualization)
        const eventStartTime = new Date();
        const eventEndTime = new Date();
        eventEndTime.setMinutes(eventStartTime.getMinutes() + 30);

        // Create the event on the "Slack Bot Meetings" calendar
        // NOTE: We do NOT add attendees here. This prevents email spam.
        // Recordings will go to whoever clicks "Record" inside the meeting.
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
    // If calendar logging fails, log error but DO NOT fail the request.
    // The user still gets their link.
    console.error("Calendar Log Error:", error);
  }
  
  return meetLink;
}

/**
 * MAIN HANDLER
 * ------------
 * Entry point for Vercel.
 */
export default async (request, response) => {
  // Ensure method is POST
  if (request.method !== 'POST') return response.status(405).send('Method Not Allowed');

  try {
    // 1. Read and Verify
    const rawBody = await getRawBody(request);
    verifyRequest(request.headers, rawBody);

    // 2. Parse Slack Payload
    const params = new URLSearchParams(rawBody);
    const text = params.get('text');
    const userId = params.get('user_id');
    const handle = params.get('user_name');

    // 3. Execute Logic
    const meetLink = await createGoogleMeet(text, userId, handle);

    // 4. Return Response (Block Kit UI)
    return response.status(200).json({
      response_type: 'in_channel', // Visible to everyone in channel
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
              style: "primary" // Green button
            }
          ]
        }
      ]
    });

  } catch (error) {
    console.error('Handler Error:', error);
    // Send a private error message to the user
    return response.status(200).json({
      response_type: 'ephemeral',
      text: `⚠️ Error: ${error.message}`,
    });
  }
};