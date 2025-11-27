/**
 * Google Meet Slack Bot
 * ---------------------
 * This serverless function handles Slash Commands from Slack (e.g., /googlemeet).
 * It verifies the request, generates a unique Google Meet link, logs it to a
 * Google Calendar for auditing, and returns a nice UI card to the user.
 */

// Import Google's library to interact with Calendar API
import { google } from 'googleapis';
// Import Crypto to verify Slack's security signature
import crypto from 'crypto';

/**
 * VERCEL CONFIGURATION
 * --------------------
 * We must disable the default JSON body parser.
 * Slack sends a raw text body, and we need that exact raw string to calculate
 * the cryptographic signature. If Vercel parses it first, the signature fails.
 */
export const config = {
  api: { bodyParser: false },
};

/**
 * HELPER: Get Raw Body
 * --------------------
 * Reads the incoming data stream and combines it into a single string.
 * Required for the security check.
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
 * Security Check: Ensures the request actually came from Slack.
 * 1. Checks for timestamp to prevent "Replay Attacks" (requests older than 5 mins).
 * 2. Hashes the body using the Signing Secret and compares it to Slack's header.
 */
function verifyRequest(headers, rawBody) {
  const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
  const timestamp = headers['x-slack-request-timestamp'];
  const slackSignature = headers['x-slack-signature'];

  if (!timestamp || !slackSignature) throw new Error('Missing headers');
  
  // Reject if timestamp is older than 5 minutes
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
  if (timestamp < fiveMinutesAgo) throw new Error('Timestamp too old');

  // Create the hash
  const baseString = `v0:${timestamp}:${rawBody}`;
  const hmac = crypto.createHmac('sha256', slackSigningSecret);
  hmac.update(baseString);
  const mySignature = `v0=${hmac.digest('hex')}`;

  // Compare hashes securely
  if (!crypto.timingSafeEqual(Buffer.from(mySignature), Buffer.from(slackSignature))) {
    throw new Error('Verification failed');
  }
}

/**
 * HELPER: Fetch Real Name
 * -----------------------
 * Slack often provides a User ID (e.g., U12345) or a Handle (e.g., 2387).
 * We use the Slack API to fetch the user's "Real Name" (e.g., Ciaran Goulding)
 * so the meeting link looks professional.
 */
async function getSlackName(userId) {
  const token = process.env.SLACK_BOT_TOKEN;
  
  if (!token) {
    console.error("❌ Error: SLACK_BOT_TOKEN is missing in Vercel vars.");
    return null;
  }

  try {
    // Use native fetch to ask Slack for user profile info
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
    console.error("❌ Slack Lookup Error:", error.message);
  }
  return null;
}

/**
 * CORE LOGIC: Create Google Meet Link
 * -----------------------------------
 * 1. Determines the meeting title.
 * 2. Sanitizes it into a URL-safe "slug".
 * 3. Creates a "Lookup Link".
 * 4. Logs the event to the designated Google Calendar.
 */
async function createGoogleMeet(text, userId, defaultHandle) {
  let rawTitle;
  let suffix = "";
  
  // --- 1. DETERMINE TITLE ---
  if (text && text.trim().length > 0) {
    // Scenario A: User typed a title (e.g., "/googlemeet Project Alpha")
    // Use it exactly as is.
    rawTitle = text;
  } else {
    // Scenario B: User typed nothing (Instant Meeting)
    // Fetch their real name to make it readable.
    const realName = await getSlackName(userId);
    const displayName = realName || defaultHandle;
    
    // Add a random 4-digit code to ensure this room is unique
    // (prevents people from joining the same "instant room" by accident)
    const randomCode = Math.floor(1000 + Math.random() * 9000);
    
    rawTitle = `${displayName}'s meeting`; 
    suffix = `-${randomCode}`;
  }

  // --- 2. SANITIZE URL ---
  // Turn "Ciaran's Meeting!" into "ciarans-meeting"
  const cleanSlug = rawTitle.toLowerCase()
    .replace(/['’]/g, '')       // Remove apostrophes
    .replace(/\s+/g, '-')       // Replace spaces with hyphens
    .replace(/[^a-z0-9-]/g, '') // Remove anything not a letter/number/hyphen
    .replace(/-+/g, '-');       // Collapse double hyphens

  // Format: meet.google.com/lookup/ciarans-meeting-8392
  const meetLink = `https://meet.google.com/lookup/${cleanSlug}${suffix}`;
  
  // --- 3. CALENDAR LOGGING ---
  // We log this to a calendar so you have a record of the meeting being created.
  try {
    const calendarId = process.env.CALENDAR_ID;
    const clientEmail = process.env.GOOGLE_CLIENT_EMAIL;
    const encodedPrivateKey = process.env.GOOGLE_PRIVATE_KEY; 

    if (calendarId && clientEmail && encodedPrivateKey) {
      // Decode the Base64 key back to a string
      let privateKey;
      try {
        privateKey = Buffer.from(encodedPrivateKey, 'base64').toString('utf8');
      } catch (e) {
        console.error("Key Decode Error:", e.message);
      }

      if (privateKey) {
        // Formatting Fix: Ensure newlines are actual line breaks
        if (privateKey.includes('\\n')) {
          privateKey = privateKey.replace(/\\n/g, '\n');
        }

        // Authenticate with Google
        const auth = new google.auth.GoogleAuth({
          credentials: { client_email: clientEmail, private_key: privateKey },
          scopes: ['https://www.googleapis.com/auth/calendar.events'],
        });

        const client = await auth.getClient();
        const calendar = google.calendar({ version: 'v3', auth: client });

        // Set meeting duration to 1 hour (visual only)
        const eventStartTime = new Date();
        const eventEndTime = new Date();
        eventEndTime.setMinutes(eventStartTime.getMinutes() + 60);

        // Insert the event
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
    // If calendar fails, log it but don't break the user's experience
    console.error("Calendar Log Error:", error);
  }
  
  return meetLink;
}

/**
 * MAIN HANDLER
 * ------------
 * This is the function executed by Vercel for every request.
 */
export default async (request, response) => {
  // Only allow POST requests (Slash commands use POST)
  if (request.method !== 'POST') return response.status(405).send('Method Not Allowed');

  try {
    // 1. Read and Verify Request
    const rawBody = await getRawBody(request);
    verifyRequest(request.headers, rawBody);

    // 2. Parse Slack Data
    const params = new URLSearchParams(rawBody);
    const text = params.get('text');
    const userId = params.get('user_id');
    const handle = params.get('user_name');

    // 3. Generate Link
    const meetLink = await createGoogleMeet(text, userId, handle);

    // 4. Respond to Slack
    // We use Block Kit to make the message look nice
    return response.status(200).json({
      response_type: 'in_channel', // Visible to everyone in the channel
      blocks: [
        {
          type: "section",
          text: {
            type: "mrkdwn",
            // The text message shown to users after entering the slash command
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
              style: "primary" // Makes the button Green
            }
          ]
        }
      ]
    });

  } catch (error) {
    console.error('Handler Error:', error);
    // Send a private error message to the user if something breaks
    return response.status(200).json({
      response_type: 'ephemeral',
      text: `⚠️ Error: ${error.message}`,
    });
  }
};