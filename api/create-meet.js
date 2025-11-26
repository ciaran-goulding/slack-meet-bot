import { google } from 'googleapis';
import crypto from 'crypto';
// REMOVED: import axios from 'axios'; <--- We don't need this anymore!

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

// --- HELPER: Fetch Real Name (Using Native 'fetch') ---
async function getSlackName(userId) {
  const token = process.env.SLACK_BOT_TOKEN;
  
  if (!token) {
    console.error("❌ Error: SLACK_BOT_TOKEN is missing in Vercel vars.");
    return null;
  }

  try {
    // We use the built-in 'fetch' instead of axios
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
      const realName = data.user.profile.real_name;
      return realName;
    } else {
      console.error("❌ Slack API Error:", data.error);
      return null;
    }
  } catch (error) {
    console.error("❌ Network Error fetching Slack name:", error.message);
  }
  return null;
}

async function createGoogleMeet(text, userId, defaultHandle) {
  let rawTitle;
  
  if (text && text.trim().length > 0) {
    rawTitle = text;
  } else {
    const realName = await getSlackName(userId);
    const displayName = realName || defaultHandle;
    rawTitle = `${displayName}'s instant meeting`;
  }

  const cleanSlug = rawTitle.toLowerCase()
    .replace(/['’]/g, '')       
    .replace(/\s+/g, '-')       
    .replace(/[^a-z0-9-]/g, '') 
    .replace(/-+/g, '-');       

  const meetLink = `https://meet.google.com/lookup/${cleanSlug}`;
  
  try {
    const calendarId = process.env.CALENDAR_ID;
    const clientEmail = process.env.GOOGLE_CLIENT_EMAIL;
    const encodedPrivateKey = process.env.GOOGLE_PRIVATE_KEY; 

    if (calendarId && clientEmail && encodedPrivateKey) {
      let privateKey;
      try {
        privateKey = Buffer.from(encodedPrivateKey, 'base64').toString('utf8');
      } catch (e) {
        console.error("Key Decode Error (continuing without calendar):", e.message);
      }

      if (privateKey) {
        // Fix newlines if needed
        if (privateKey.includes('\\n')) {
          privateKey = privateKey.replace(/\\n/g, '\n');
        }

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
    const userId = params.get('user_id');
    const handle = params.get('user_name');

    const meetLink = await createGoogleMeet(text, userId, handle);

    return response.status(200).json({
      response_type: 'in_channel',
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
              style: "primary"
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