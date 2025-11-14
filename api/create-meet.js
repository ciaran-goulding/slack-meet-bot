/*
 * File: api/create-meet.js
 * Description: Vercel serverless function to handle a Slack slash command ("/googlemeet").
 * This function securely creates a new, unique Google Meet link for each command
 * by creating an event on a dedicated "bot" calendar using a Google Service Account.
 * This method is ad-hoc, non-blocking, and avoids all user-based OAuth flows.
 */

// --- DEPENDENCIES ---

// Import the official Google APIs client library for Node.js
import { google } from 'googleapis';
// Import the built-in Node.js 'crypto' module.
// This is required to perform cryptographic operations for verifying Slack's request signature.
import crypto from 'crypto';

// --- VERCEL CONFIGURATION ---

// This Vercel-specific config object is crucial.
// It tells Vercel *not* to parse the incoming request body.
// We need the *raw, unparsed body* (as a string) to verify
// the Slack request signature (see verifyRequest function).
export const config = {
  api: {
    bodyParser: false,
  },
};

// --- HELPER FUNCTIONS ---

/**
 * Asynchronously reads the raw body from the request stream.
 * Vercel's `request` object is a stream. We need to "consume" this
 * stream to get the full body content as a single string.
 * @param {object} req - The Vercel request object.
 * @returns {Promise<string>} The raw request body as a string.
 */
async function getRawBody(req) {
  const chunks = [];
  // Iterate over the stream and collect all data "chunks"
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  // Combine all chunks into a single Buffer, then convert to a string.
  return Buffer.concat(chunks).toString();
}

/**
 * Verifies that the incoming request is genuinely from Slack.
 * This is a critical security step to prevent forged requests.
 * See: https://api.slack.com/authentication/verifying-requests-from-slack
 * @param {object} headers - The headers from the Vercel request object.
 * @param {string} rawBody - The raw string body from getRawBody().
 * @throws {Error} If headers are missing or signature is invalid.
 */
function verifyRequest(headers, rawBody) {
  // 1. Get Slack's signing secret from environment variables.
  const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;

  // 2. Get the headers sent by Slack.
  const timestamp = headers['x-slack-request-timestamp'];
  const slackSignature = headers['x-slack-signature'];

  // 3. Check for missing headers.
  if (!timestamp || !slackSignature) {
    throw new Error('Missing Slack signature headers (x-slack-request-timestamp or x-slack-signature)');
  }

  // 4. Prevent replay attacks: Check if the timestamp is older than 5 minutes.
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
  if (timestamp < fiveMinutesAgo) {
    throw new Error('Request timestamp is too old. Possible replay attack.');
  }

  // 5. Construct the "base string" that Slack used to create its signature.
  // Format is: "v0:" + timestamp + ":" + rawBody
  const baseString = `v0:${timestamp}:${rawBody}`;

  // 6. Create our *own* signature using the same method as Slack.
  // We use our secret to create an HMAC-SHA256 hash of the base string.
  const hmac = crypto.createHmac('sha256', slackSigningSecret);
  hmac.update(baseString);
  const mySignature = `v0=${hmac.digest('hex')}`;

  // 7. Compare our signature to Slack's signature.
  // We MUST use crypto.timingSafeEqual to prevent "timing attacks".
  // Do not use a simple "==" string comparison.
  if (!crypto.timingSafeEqual(Buffer.from(mySignature), Buffer.from(slackSignature))) {
    throw new Error('Slack signature verification failed. Request is not from Slack.');
  }
  // If we reach here, the signature is valid.
}

/**
 * Creates a new Google Meet link by creating an event on the bot's calendar.
 * This function authenticates using a Service Account (JWT) and inserts a
 * new event, which automatically generates a unique Meet link.
 * @param {string} text - The optional text the user typed after /googlemeet.
 * @returns {Promise<string>} The unique Google Meet URL (e.g., "https.meet.google.com/xxx-xxxx-xxx").
 * @throws {Error} If environment variables are missing or Google API fails.
 */
async function createGoogleMeet(text) {
  // 1. Get required environment variables.
  // CALENDAR_ID is the ID of the "dummy" bot calendar (e.g., "...@group.calendar.google.com").
  const calendarId = process.env.CALENDAR_ID;
  // GCP_CREDS_BASE64 is the base64-encoded JSON key file for the Service Account.
  const credsBase64 = process.env.GCP_CREDS_BASE64;

  // --- START: DEBUG LOGS ---
  // Let's check if the variables are being loaded at all.
  console.log('CALENDAR_ID (first 10):', calendarId ? calendarId.substring(0, 10) : 'CALENDAR_ID IS UNDEFINED');
  console.log('GCP_CREDS_BASE64 (first 10):', credsBase64 ? credsBase64.substring(0, 10) : 'CREDS_BASE64 IS UNDEFINED');
  // --- END: DEBUG LOGS ---

  if (!calendarId || !credsBase64) {
    throw new Error('Server configuration error: Missing CALENDAR_ID or GCP_CREDS_BASE64 env variables.');
  }

  // 2. Decode the Service Account key from Base64 back into JSON.
  const decodedKey = Buffer.from(credsBase64, 'base64').toString('utf8');
  const credentials = JSON.parse(decodedKey);

  // 3. Authenticate as the Service Account (JWT - JSON Web Token).
  // We tell Google we are this bot ("client_email") and prove it with
  // our private key. We request permission to manage calendar events.
  const auth = new google.auth.JWT(
    credentials.client_email,
    null,
    credentials.private_key,
    ['https://www.googleapis.com/auth/calendar.events']
  );

  // 4. Initialize the Google Calendar API client with our auth credentials.
  const calendar = google.calendar({ version: 'v3', auth });

  // 5. Define the start and end time for the "dummy" event (e.g., 1 hour from now).
  // These times don't really matter, as the link is instant and perpetual.
  const eventStartTime = new Date();
  const eventEndTime = new Date();
  eventEndTime.setMinutes(eventStartTime.getMinutes() + 60);

  // 6. Define the calendar event resource.
  // The 'conferenceData' object is the magic part.
  // It tells Google, "Please create a new conference room for this event."
  const event = {
    summary: text || 'New Slack Meeting', // Use user's text as the event title.
    description: 'Meeting created by the Slack /googlemeet command.',
    start: { dateTime: eventStartTime.toISOString(), timeZone: 'UTC' },
    end: { dateTime: eventEndTime.toISOString(), timeZone: 'UTC' },
    conferenceData: {
      createRequest: {
        // A unique ID for this creation request.
        requestId: `slack-meet-${Date.now()}`,
        // Specify that we want a 'hangoutsMeet' (Google Meet) room.
        conferenceSolutionKey: { type: 'hangoutsMeet' },
      },
    },
  };

  // 7. Call the Google Calendar API to insert the event.
  // This is the main API call. It creates the event on the 'CALENDAR_ID'
  // and returns the event data, including the new Meet link.
  const res = await calendar.events.insert({
    calendarId: calendarId,
    resource: event,
    conferenceDataVersion: 1, // Required when using conferenceData
  });

  // 8. Return the unique link.
  // This link is instantly usable and does not depend on the event's start/end time.
  return res.data.hangoutLink;
}

// --- MAIN HANDLER (Vercel Serverless Function) ---

/**
 * This is the main entry point for the Vercel serverless function.
 * It handles the incoming POST request from Slack's slash command.
 * @param {object} request - The Vercel request object.
 * @param {object} response - The Vercel response object.
 */
export default async (request, response) => {
  // 1. Only allow POST requests. Slash commands are always POST.
  if (request.method !== 'POST') {
    return response.status(405).send('Method Not Allowed');
  }

  let rawBody;
  try {
    // 2. Get the raw body for signature verification.
    rawBody = await getRawBody(request);
    
    // 3. Verify the request is from Slack. If not, this throws an error.
    verifyRequest(request.headers, rawBody);

  } catch (error) {
    // If verification fails, log it and send a 403 Forbidden.
    console.warn('Slack verification failed:', error.message);
    return response.status(403).send('Slack signature verification failed.');
  }

  try {
    // 4. Parse the verified Slack body.
    // Slack sends its slash command data as URL-encoded form data.
    const params = new URLSearchParams(rawBody);
    // 'text' is anything the user typed after the command (e.g., "/googlemeet My Quick Call")
    const text = params.get('text'); 

    // 5. Call our function to create the Google Meet link.
    const meetLink = await createGoogleMeet(text);

    // 6. Format a rich response for Slack using "Block Kit".
    // This creates a nice-looking message with a button.
    let messageText = `Here's your new Google Meet link:`;
    if (text) {
      messageText = `Here's the Google Meet link for: *${text}*`;
    }

    const slackResponse = {
      // 'in_channel' makes the response visible to everyone in the channel.
      // Use 'ephemeral' to make it visible only to the user who ran the command.
      response_type: 'in_channel', 
      blocks: [
        {
          type: 'section',
          text: { type: 'mrkdwn', text: messageText },
        },
        {
          type: 'actions',
          elements: [
            {
              type: 'button',
              text: { type: 'plain_text', text: 'Join Meeting', emoji: true },
              url: meetLink, // The link for the button.
              style: 'primary',
              accessibility_label: 'Button to join the Google Meet call',
            },
          ],
        },
      ],
    };

    // 7. Send the successful 200 OK response back to Slack.
    // Slack requires a 200 OK within 3 seconds, or it will show an error.
    return response.status(200).json(slackResponse);

  } catch (error) {
    // 8. Handle any errors from our code (e.g., Google API failure).
    console.error('Error in main handler:', error);
    
    // Send a user-facing error message back to Slack.
    // 'ephemeral' is good here so we don't spam the channel with errors.
    return response.status(200).json({
      response_type: 'ephemeral',
      text: `Sorry, I couldn't create a meeting. Error: ${error.message}`,
    });
  }
};