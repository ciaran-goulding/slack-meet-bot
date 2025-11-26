// File: api/create-meet.js
import { google } from 'googleapis';
import crypto from 'crypto';

export const config = {
  api: {
    bodyParser: false,
  },
};

async function getRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString();
}

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

async function createGoogleMeet(text) {
  const calendarId = process.env.CALENDAR_ID;
  const rawCreds = process.env.GCP_CREDS_BASE64; // This is now Raw JSON, not Base64

  if (!calendarId || !rawCreds) {
    throw new Error('Server config error: Missing CALENDAR_ID or GCP_CREDS_BASE64');
  }

  // 1. Parse the JSON directly
  let credentials;
  try {
    credentials = JSON.parse(rawCreds);
  } catch (e) {
    throw new Error('Failed to parse GCP credentials. Make sure it is valid JSON.');
  }

  // 2. CRITICAL FIX: Repair the Private Key format
  // Sometimes environment variables turn real newlines (\n) into string literals (\\n).
  // This line fixes that, which solves the 401 error.
  const privateKey = credentials.private_key.replace(/\\n/g, '\n');

  const auth = new google.auth.JWT(
    credentials.client_email,
    null,
    privateKey, // Use the fixed key
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

export default async (request, response) => {
  if (request.method !== 'POST') {
    return response.status(405).send('Method Not Allowed');
  }

  try {
    const rawBody = await getRawBody(request);
    verifyRequest(request.headers, rawBody);

    const params = new URLSearchParams(rawBody);
    const text = params.get('text');

    const meetLink = await createGoogleMeet(text);

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

    return response.status(200).json(slackResponse);

  } catch (error) {
    console.error('Error handling command:', error);
    return response.status(200).json({
      response_type: 'ephemeral',
      text: `⚠️ Sorry, I couldn't create the meeting. Error: ${error.message}`,
    });
  }
};