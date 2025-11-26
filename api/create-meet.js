// File: api/create-meet.js

// Import the Google APIs library to talk to Google Calendar
import { google } from 'googleapis';
// Import Crypto to handle the mathematical hashing for Slack security verification
import crypto from 'crypto';

/**
 * VERCEL CONFIGURATION
 * --------------------
 * By default, Vercel parses the incoming request body into JSON.
 * However, Slack's security signature is based on the RAW, unparsed text body.
 * If Vercel parses it first, the signature check will fail.
 * We disable the body parser here so we can read the raw stream manually.
 */
export const config = {
  api: { bodyParser: false },
};

/**
 * HELPER: GET RAW BODY
 * --------------------
 * Reads the raw data stream from the HTTP request and converts it 
 * into a single string. This is required for crypto verification.
 */
async function getRawBody(req) {
  const chunks = [];
  // Loop through the data stream chunks
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  // Combine all chunks into one buffer and convert to string
  return Buffer.concat(chunks).toString();
}

/**
 * HELPER: VERIFY SLACK REQUEST
 * ----------------------------
 * Security Check! We ensure this request actually came from Slack 
 * and not a hacker trying to spam your bot.
 * * 1. We take the raw body and the timestamp.
 * 2. We hash them using your SLACK_SIGNING_SECRET.
 * 3. We compare our hash to the signature Slack sent in the headers.
 */
function verifyRequest(headers, rawBody) {
  const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
  const timestamp = headers['x-slack-request-timestamp'];
  const slackSignature = headers['x-slack-signature'];

  // Check if the necessary headers exist
  if (!timestamp || !slackSignature) throw new Error('Missing headers');
  
  // Replay Attack Protection: Reject requests older than 5 minutes
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
  if (timestamp < fiveMinutesAgo) throw new Error('Timestamp too old');

  // Create the "Basestring" (Version + Timestamp + Body)
  const baseString = `v0:${timestamp}:${rawBody}`;
  
  // Create the HMAC-SHA256 hash using your secret
  const hmac = crypto.createHmac('sha256', slackSigningSecret);
  hmac.update(baseString);
  const mySignature = `v0=${hmac.digest('hex')}`;

  // Compare the signatures securely (constant-time comparison)
  if (!crypto.timingSafeEqual(Buffer.from(mySignature), Buffer.from(slackSignature))) {
    throw new Error('Verification failed');
  }
}

/**
 * LOGIC: CREATE GOOGLE MEET LINK
 * ------------------------------
 * This function generates a unique link and logs it to the calendar.
 */
async function createGoogleMeet(text) {
  // Retrieve environment variables
  const calendarId = process.env.CALENDAR_ID;
  const clientEmail = process.env.GOOGLE_CLIENT_EMAIL;
  // This is the Base64 string we generated to safely store the private key
  const encodedPrivateKey = process.env.GOOGLE_PRIVATE_KEY; 

  // Basic validation to ensure environment variables are set
  if (!calendarId || !clientEmail || !encodedPrivateKey) {
    throw new Error('Missing config variables');
  }

  // --- STRATEGY: THE "LOOKUP" LINK ---
  // Since Service Accounts on free projects cannot generate "Conference Data" via API,
  // we generate a unique ID client-side.
  // URL Format: meet.google.com/lookup/{unique_id}
  // When a user clicks this, Google dynamically creates a secure room for that ID.
  const uniqueId = `slack-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
  const meetLink = `https://meet.google.com/lookup/${uniqueId}`;

  // --- AUTHENTICATION ---
  // Decode the Base64 Private Key back into a real string
  let privateKey;
  try {
    privateKey = Buffer.from(encodedPrivateKey, 'base64').toString('utf8');
  } catch (e) {
    throw new Error('Failed to decode Private Key');
  }

  // Set up Google Authentication
  const auth = new google.auth.GoogleAuth({
    credentials: {
      client_email: clientEmail,
      private_key: privateKey,
    },
    // We only need permission to edit events
    scopes: ['https://www.googleapis.com/auth/calendar.events'],
  });

  // Create the API client
  const client = await auth.getClient();
  const calendar = google.calendar({ version: 'v3', auth: client });

  // --- CALENDAR LOGGING ---
  // We create a calendar event so you have a record of the meeting.
  // We set the time for "Now" to "1 Hour from Now".
  const eventStartTime = new Date();
  const eventEndTime = new Date();
  eventEndTime.setMinutes(eventStartTime.getMinutes() + 60);

  const event = {
    summary: text || 'New Slack Meeting',
    // We put the unique link in the description and location fields
    description: `Meeting created by Slack.\n\nClick here to join: ${meetLink}`,
    location: meetLink, 
    start: { dateTime: eventStartTime.toISOString(), timeZone: 'UTC' },
    end: { dateTime: eventEndTime.toISOString(), timeZone: 'UTC' },
    // NOTE: We do NOT use "conferenceData" here to avoid the 400 Error.
  };

  // Insert the event into the "Slack Bot Meetings" calendar
  await calendar.events.insert({
    calendarId: calendarId,
    resource: event,
  });

  // Return the unique link so we can send it to Slack
  return meetLink;
}

/**
 * MAIN HANDLER
 * ------------
 * This is the entry point that Vercel runs when a request hits the URL.
 */
export default async (request, response) => {
  // Slack slash commands always use POST
  if (request.method !== 'POST') return response.status(405).send('Method Not Allowed');

  try {
    // 1. Get the raw body string
    const rawBody = await getRawBody(request);
    
    // 2. Verify the security signature
    verifyRequest(request.headers, rawBody);

    // 3. Parse the URL-encoded body sent by Slack
    // (e.g., "user_name=ciaran&text=Project+meeting")
    const params = new URLSearchParams(rawBody);
    const text = params.get('text'); // The text typed after /googlemeet

    // 4. Run our logic to generate the link and log to calendar
    const meetLink = await createGoogleMeet(text);

    // 5. Customize the response message
    let messageText = text ? `Here's the Google Meet link for: *${text}*` : `Here's your new Google Meet link:`;

    // 6. Build the Slack Block Kit JSON
    // 'in_channel' makes the response visible to everyone in the channel
    return response.status(200).json({
      response_type: 'in_channel',
      blocks: [
        { type: 'section', text: { type: 'mrkdwn', text: messageText } },
        { 
          type: 'actions', 
          elements: [{ 
            type: 'button', 
            text: { type: 'plain_text', text: 'Join Meeting', emoji: true }, 
            url: meetLink, // The unique link we generated
            style: 'primary' // Makes the button green
          }] 
        },
      ],
    });

  } catch (error) {
    console.error('Handler Error:', error);
    
    // If something goes wrong, return a 200 OK to Slack (so it doesn't show a system error),
    // but send an "ephemeral" message (visible only to user) explaining the crash.
    return response.status(200).json({
      response_type: 'ephemeral',
      text: `⚠️ Error: ${error.message}`,
    });
  }
};