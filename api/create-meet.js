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
  const uniqueId = `slack-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
  const meetLink = `https://meet.google.com/lookup/${uniqueId}`;

  // We try to log to calendar, but if it fails, we still return the link
  try {
    const calendarId = process.env.CALENDAR_ID;
    const clientEmail = process.env.GOOGLE_CLIENT_EMAIL;
    const encodedPrivateKey = process.env.GOOGLE_PRIVATE_KEY; 

    if (calendarId && clientEmail && encodedPrivateKey) {
      const privateKey = Buffer.from(encodedPrivateKey, 'base64').toString('utf8');
      
      const auth = new google.auth.GoogleAuth({
        credentials: { client_email: clientEmail, private_key: privateKey },
        scopes: ['https://www.googleapis.com/auth/calendar.events'],
      });

      const client = await auth.getClient();
      const calendar = google.calendar({ version: 'v3', auth: client });

      const eventStartTime = new Date();
      const eventEndTime = new Date();
      eventEndTime.setMinutes(eventStartTime.getMinutes() + 60);

      await calendar.events.insert({
        calendarId: calendarId,
        resource: {
          summary: text || 'New Slack Meeting',
          description: `Meeting created by Slack.\nJoin: ${meetLink}`,
          location: meetLink,
          start: { dateTime: eventStartTime.toISOString(), timeZone: 'UTC' },
          end: { dateTime: eventEndTime.toISOString(), timeZone: 'UTC' },
        },
      });
    }
  } catch (error) {
    console.error("Calendar Log Error:", error);
  }
  
  return meetLink;
}

export default async (request, response) => {
  if (request.method !== 'POST') return response.status(405).send('Method Not Allowed');

  try {
    const rawBody = await getRawBody(request);
    verifyRequest(request.headers, rawBody);

    const params = new URLSearchParams(rawBody);
    const text = params.get('text');

    const meetLink = await createGoogleMeet(text);

    // --- THE UI UPDATE ---
    // Here is the simplified look you requested
    return response.status(200).json({
      response_type: 'in_channel',
      blocks: [
        {
          type: "section",
          text: {
            type: "mrkdwn",
            // UPDATED TEXT HERE
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
    return response.status(200).json({
      response_type: 'ephemeral',
      text: `⚠️ Error: ${error.message}`,
    });
  }
};