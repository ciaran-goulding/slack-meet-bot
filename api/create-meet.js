// File: api/create-meet.js
// This is the new Vercel-compatible code

import { google } from 'googleapis';
import crypto from 'crypto';

// 1. Tell Vercel NOT to parse the body. We need the raw body for Slack.
export const config = {
  api: {
    bodyParser: false,
  },
};

// 2. Helper function to read the raw body from the request stream
async function getRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString();
}

// 3. Helper function to verify the Slack request
function verifyRequest(headers, rawBody) {
  const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
  const timestamp = headers['x-slack-request-timestamp'];
  const slackSignature = headers['x-slack-signature'];

  if (!timestamp || !slackSignature) {
    throw new Error('Missing Slack signature headers');
  }

  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
  if (timestamp < fiveMinutesAgo) {
    throw new Error('Request timestamp is too old.');
  }

  const baseString = `v0:${timestamp}:${rawBody}`;
  const hmac = crypto.createHmac('sha256', slackSigningSecret);
  hmac.update(baseString);
  const mySignature = `v0=${hmac.digest('hex')}`;

  if (!crypto.timingSafeEqual(Buffer.from(mySignature), Buffer.from(slackSignature))) {
    throw new Error('Slack signature verification failed.');
  }
}

// 4. Helper function to create the Meet link (same as before)
async function createGoogleMeet(text) {
  const calendarId = process.env.CALENDAR_ID;
  const credsBase64 = process.env.GCP_CREDS_BASE64;

  if (!calendarId || !credsBase64) {
    throw new Error('Server config error: Missing CALENDAR_ID or GCP_CREDS_BASE64');
  }

  const decodedKey = Buffer.from(credsBase64, 'base64').toString('utf8');
  const credentials = JSON.parse(decodedKey);

  const auth = new google.auth.JWT(
    credentials.client_email,
    null,
    credentials.private_key,
    ['https://www.googleapis.com/auth/calendar.events']
  );

  const calendar = google.calendar({ version: 'v3', auth });

  const eventStartTime = new Date();
  const eventEndTime = new Date();
  eventEndTime.setMinutes(eventStartTime.getMinutes() + 60);

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

  const res = await calendar.events.insert({
    calendarId: calendarId,
    resource: event,
    conferenceDataVersion: 1,
  });

  return res.data.hangoutLink;
}

// 5. This is the MAIN function Vercel will run
export default async (request, response) => {
  // We only accept POST requests
  if (request.method !== 'POST') {
    return response.status(405).send('Method Not Allowed');
  }

  let rawBody;
  try {
    // 1. Get the raw body
    rawBody = await getRawBody(request);
    
    // 2. Verify the request is from Slack
    verifyRequest(request.headers, rawBody);

  } catch (error) {
    console.warn('Slack verification failed:', error.message);
    return response.status(403).send('Slack signature verification failed.');
  }

  try {
    // 3. Parse the body (which is URL-encoded)
    const params = new URLSearchParams(rawBody);
    const userName = params.get('user_name') || 'there';
    const text = params.get('text');

    // 4. Create the Google Meet link
    const meetLink = await createGoogleMeet(text);

    // 5. Format the Slack response
    let messageText = `Here's your new Google Meet link:`;
    if (text) {
      messageText = `Here's the Google Meet link for: *${text}*`;
    }

    const slackResponse = {
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
              url: meetLink,
              style: 'primary',
              accessibility_label: 'Button to join the Google Meet call',
            },
          ],
        },
      ],
    };

    // 6. Send the JSON response back to Slack
    return response.status(200).json(slackResponse);

  } catch (error) {
    console.error('Error in main handler:', error);
    // Send a user-facing error message back to Slack
    return response.status(200).json({
      response_type: 'ephemeral',
      text: `Sorry, I couldn't create a meeting. Error: ${error.message}`,
    });
  }
};