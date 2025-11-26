// File: api/create-meet.js

// Import Google's library to talk to the Calendar API
import { google } from 'googleapis';
// Import Crypto to handle the security math for verifying Slack requests
import crypto from 'crypto';

/**
 * VERCEL CONFIGURATION
 * --------------------
 * Vercel tries to automatically parse JSON bodies.
 * We must disable this because Slack verification requires the RAW, 
 * un-touched request body string to calculate the signature hash.
 */
export const config = {
  api: { bodyParser: false },
};

/**
 * HELPER: GET RAW BODY
 * --------------------
 * Reads the incoming data stream from Slack and converts it into a single string.
 */
async function getRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString();
}

/**
 * HELPER: VERIFY SLACK REQUEST
 * ----------------------------
 * This ensures the request actually came from Slack and not a hacker.
 * It hashes the timestamp + body using your Signing Secret and compares
 * it to the signature Slack sent in the headers.
 */
function verifyRequest(headers, rawBody) {
  const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
  const timestamp = headers['x-slack-request-timestamp'];
  const slackSignature = headers['x-slack-signature'];

  // 1. Check if headers exist
  if (!timestamp || !slackSignature) throw new Error('Missing headers');
  
  // 2. Check for "Replay Attacks" (reject requests older than 5 mins)
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
  if (timestamp < fiveMinutesAgo) throw new Error('Timestamp too old');

  // 3. Create the hash
  const baseString = `v0:${timestamp}:${rawBody}`;
  const hmac = crypto.createHmac('sha256', slackSigningSecret);
  hmac.update(baseString);
  const mySignature = `v0=${hmac.digest('hex')}`;

  // 4. Compare hashes securely
  if (!crypto.timingSafeEqual(Buffer.from(mySignature), Buffer.from(slackSignature))) {
    throw new Error('Verification failed');
  }
}

/**
 * LOGIC: CREATE GOOGLE MEET LINK
 * ------------------------------
 * This handles the logic of naming the meeting and logging it to the calendar.
 */
async function createGoogleMeet(text, userName) {
  // --- STEP 1: DETERMINE THE MEETING TITLE ---
  let rawTitle;
  
  if (text && text.trim().length > 0) {
    // If the user typed a specific name (e.g., "Project Alpha"), use it.
    rawTitle = text;
  } else {
    // If the user left it blank, default to "Ciaran's instant meeting"
    rawTitle = `${userName}'s instant meeting`;
  }

  // --- STEP 2: SANITIZE FOR URL ---
  // Browsers cannot handle spaces or special characters (like ' or !) in URLs.
  // We clean the title to make a valid "slug".
  const cleanSlug = rawTitle.toLowerCase()
    .replace(/['’]/g, '')       // Remove apostrophes (Ciaran's -> Ciarans)
    .replace(/\s+/g, '-')       // Replace spaces with hyphens (instant meeting -> instant-meeting)
    .replace(/[^a-z0-9-]/g, '') // Remove anything that isn't a letter, number, or hyphen
    .replace(/-+/g, '-');       // Remove double hyphens if they appeared

  // Create the "Lookup" Link.
  // When a user clicks this, Google checks if a room with this name exists.
  // If not, it creates it.
  const meetLink = `https://meet.google.com/lookup/${cleanSlug}`;
  
  // --- STEP 3: LOG TO CALENDAR (OPTIONAL) ---
  // We attempt to add this to the calendar for your records.
  try {
    const calendarId = process.env.CALENDAR_ID;
    const clientEmail = process.env.GOOGLE_CLIENT_EMAIL;
    // Get the safe key from Vercel env
    const encodedPrivateKey = process.env.GOOGLE_PRIVATE_KEY; 

    // Only proceed if we have all credentials
    if (calendarId && clientEmail && encodedPrivateKey) {
      // Unwrap the safe Base64 key back to text
      const privateKey = Buffer.from(encodedPrivateKey, 'base64').toString('utf8');
      
      // Authenticate with Google
      const auth = new google.auth.GoogleAuth({
        credentials: { client_email: clientEmail, private_key: privateKey },
        scopes: ['https://www.googleapis.com/auth/calendar.events'],
      });

      const client = await auth.getClient();
      const calendar = google.calendar({ version: 'v3', auth: client });

      // Set duration for 1 hour (just for the calendar visual)
      const eventStartTime = new Date();
      const eventEndTime = new Date();
      eventEndTime.setMinutes(eventStartTime.getMinutes() + 60);

      // Create the event
      await calendar.events.insert({
        calendarId: calendarId,
        resource: {
          summary: rawTitle, // Use the pretty, readable title for the calendar
          description: `Meeting created by Slack.\nJoin: ${meetLink}`,
          location: meetLink,
          start: { dateTime: eventStartTime.toISOString(), timeZone: 'UTC' },
          end: { dateTime: eventEndTime.toISOString(), timeZone: 'UTC' },
        },
      });
    }
  } catch (error) {
    // If the calendar fails (e.g., bad permissions), we just log the error 
    // but allow the code to continue so the user still gets their link.
    console.error("Calendar Log Error:", error);
  }
  
  return meetLink;
}

/**
 * MAIN HANDLER
 * ------------
 * This is the function Vercel executes when the URL is hit.
 */
export default async (request, response) => {
  // Only accept POST requests
  if (request.method !== 'POST') return response.status(405).send('Method Not Allowed');

  try {
    // 1. Get raw body & Verify
    const rawBody = await getRawBody(request);
    verifyRequest(request.headers, rawBody);

    // 2. Parse the parameters Slack sent us
    const params = new URLSearchParams(rawBody);
    const text = params.get('text');
    // We grab the username so we can auto-name the meeting if 'text' is empty
    const userName = params.get('user_name') || 'User'; 

    // 3. Generate the Link
    const meetLink = await createGoogleMeet(text, userName);

    // 4. Send the response back to Slack
    return response.status(200).json({
      response_type: 'in_channel', // 'in_channel' = visible to everyone
      blocks: [
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: "Click below to join your Google Meet meeting"
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
    // If something breaks, tell the user privately ('ephemeral')
    return response.status(200).json({
      response_type: 'ephemeral',
      text: `⚠️ Error: ${error.message}`,
    });
  }
};