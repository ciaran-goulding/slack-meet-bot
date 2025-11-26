import { google } from 'googleapis';
import crypto from 'crypto';

export const config = {
  api: { bodyParser: false },
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

  if (!timestamp || !slackSignature) throw new Error('Missing headers');
  
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
  if (timestamp < fiveMinutesAgo) throw new Error('Timestamp too old');

  const baseString = `v0:${timestamp}:${rawBody}`;
  const hmac = crypto.createHmac('sha256', slackSigningSecret);
  hmac.update(baseString);
  const mySignature = `v0=${hmac.digest('hex')}`;

  if (!crypto.timingSafeEqual(Buffer.from(mySignature), Buffer.from(slackSignature))) {
    throw new Error('Verification failed');
  }
}

async function createGoogleMeet(text) {
  const calendarId = process.env.CALENDAR_ID;
  const clientEmail = process.env.GOOGLE_CLIENT_EMAIL;
  const privateKeyString = process.env.GOOGLE_PRIVATE_KEY;

  if (!calendarId || !clientEmail || !privateKeyString) {
    throw new Error('Missing config: Check CALENDAR_ID, GOOGLE_CLIENT_EMAIL, and GOOGLE_PRIVATE_KEY');
  }

  // --- THE FINAL KEY FIX ---
  // Vercel turns newlines into literal "\n" characters. We must turn them back.
  // We also remove any accidental quotes if they were pasted in.
  const privateKey = privateKeyString
    .replace(/\\n/g, '\n')   // Convert literal \n to real newlines
    .replace(/"/g, '');      // Remove any extra quotes

  console.log("Using Email:", clientEmail); 
  // -------------------------

  const auth = new google.auth.GoogleAuth({
    credentials: {
      client_email: clientEmail,
      private_key: privateKey,
    },
    scopes: ['https://www.googleapis.com/auth/calendar.events'],
  });

  const client = await auth.getClient();
  const calendar = google.calendar({ version: 'v3', auth: client });

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
  if (request.method !== 'POST') return response.status(405).send('Method Not Allowed');

  try {
    const rawBody = await getRawBody(request);
    verifyRequest(request.headers, rawBody);

    const params = new URLSearchParams(rawBody);
    const text = params.get('text');

    const meetLink = await createGoogleMeet(text);

    let messageText = text ? `Here's the Google Meet link for: *${text}*` : `Here's your new Google Meet link:`;

    return response.status(200).json({
      response_type: 'in_channel',
      blocks: [
        { type: 'section', text: { type: 'mrkdwn', text: messageText } },
        { type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: 'Join Meeting', emoji: true }, url: meetLink, style: 'primary' }] },
      ],
    });

  } catch (error) {
    console.error('Handler Error:', error);
    return response.status(200).json({
      response_type: 'ephemeral',
      text: `⚠️ Error: ${error.message}`,
    });
  }
};