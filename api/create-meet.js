// File: api/create-meet.js
import { google } from 'googleapis';
import crypto from 'crypto';

// 1. Vercel Config: Tell Vercel NOT to parse the body automatically.
// We need the raw raw body buffer to verify the Slack signature.
export const config = {
  api: {
    bodyParser: false,
  },
};

// 2. Helper: Read the raw body from the request stream
async function getRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString();
}

// 3. Helper: Verify the request actually came from Slack
function verifyRequest(headers, rawBody) {
  const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
  const timestamp = headers['x-slack-request-timestamp'];
  const slackSignature = headers['x-slack-signature'];

  // Check if headers exist
  if (!timestamp || !slackSignature) {
    throw new Error('Missing Slack signature headers');
  }

  // Check for replay attacks (timestamp < 5 minutes old)
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
  if (timestamp < fiveMinutesAgo) {
    throw new Error('Request timestamp is too old.');
  }

  // Verify signature
  const baseString = `v0:${timestamp}:${rawBody}`;
  const hmac = crypto.createHmac('sha256', slackSigningSecret);
  hmac.update(baseString);
  const mySignature = `v0=${hmac.digest('hex')}`;

  if (!crypto.timingSafeEqual(Buffer.from(mySignature), Buffer.from(slackSignature))) {
    throw new Error('Slack signature verification failed.');
  }
}

// 4. Helper: Create the Google Meet link
async function createGoogleMeet(text) {
  // Get variables
  // NOTE: Set CALENDAR_ID to 'primary' in Vercel to use the robot's own calendar
  const calendarId = process.env.CALENDAR_ID; 
  const credsBase64 = process.env.GCP_CREDS_BASE64;

  if (!calendarId || !credsBase64) {
    throw new Error('Server config error: Missing CALENDAR_ID or GCP_CREDS_BASE64');
  }

  // Decode the Base64 key
  const decodedKey = Buffer.from(credsBase64, 'base64').toString('utf8');
  const credentials = JSON.parse(decodedKey);

  // Authenticate the Robot (Service Account)
  const auth = new google.auth.JWT(
    credentials.client_email,
    null,
    credentials.private_key,
    ['https://www.googleapis.com/auth/calendar.events']
  );

  const calendar = google.calendar({ version: 'v3', auth });

  // Set up the event time (1 hour from now)
  const eventStartTime = new Date();
  const eventEndTime = new Date();
  eventEndTime.setMinutes(eventStartTime.getMinutes() + 60);

  // Define the event
  const event = {
    summary: text || 'New Slack Meeting',
    description: 'Meeting created by the Slack /googlemeet command.',
    start: { dateTime: eventStartTime.toISOString(), timeZone: 'UTC' },
    end: { dateTime: eventEndTime.toISOString(), timeZone: 'UTC' },
    conferenceData: {
      createRequest: {
        requestId: `slack-meet-${Date.now()}`,
        conferenceSolutionKey: { type: 'hangoutsMeet' },
      },
    },
  };

  // Insert event into Google Calendar
  const res = await calendar.events.insert({
    calendarId: calendarId,
    resource: event,
    conferenceDataVersion: 1,
  });

  // Return the generated link
  return res.data.hangoutLink;
}

// 5. Main Vercel Function Handler
export default async (request, response) => {
  // Only allow POST requests
  if (request.method !== 'POST') {
    return response.status(405).send('Method Not Allowed');
  }

  try {
    // A. Get Raw Body & Verify Slack
    const rawBody = await getRawBody(request);
    verifyRequest(request.headers, rawBody);

    // B. Parse the data (it comes as a URL-encoded string)
    const params = new URLSearchParams(rawBody);
    const userName = params.get('user_name') || 'there';
    const text = params.get('text'); // "Team Meeting"

    // C. Create the Google Meet Link
    const meetLink = await createGoogleMeet(text);

    // D. Build the Slack Message
    let messageText = `Here's your new Google Meet link:`;
    if (text) {
      messageText = `Here's the Google Meet link for: *${text}*`;
    }

    const slackResponse = {
      response_type: 'in_channel', // Public message
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
              url: meetLink,
              style: 'primary', // Green button
              accessibility_label: 'Button to join the Google Meet call',
            },
          ],
        },
      ],
    };

    // E. Send Success Response
    return response.status(200).json(slackResponse);

  } catch (error) {
    console.error('Error handling command:', error);
    
    // Send a polite error message back to the user
    return response.status(200).json({
      response_type: 'ephemeral', // Only visible to user
      text: `⚠️ Sorry, I couldn't create the meeting. Error: ${error.message}`,
    });
  }
};