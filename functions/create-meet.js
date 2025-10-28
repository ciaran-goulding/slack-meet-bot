// File: netlify/functions/create-meet.js

const crypto = require('crypto');
const { google } = require('googleapis'); // <-- NEW: Google API library

// --- Helper Function: Verify Slack Request ---
// (This is your existing security code)
function verifyRequest(event) {
  const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
  const timestamp = event.headers['x-slack-request-timestamp'];
  const slackSignature = event.headers['x-slack-signature'];
  const requestBody = event.body;

  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
  if (timestamp < fiveMinutesAgo) {
    throw new Error('Request timestamp is too old.');
  }

  const baseString = `v0:${timestamp}:${requestBody}`;
  const hmac = crypto.createHmac('sha256', slackSigningSecret);
  hmac.update(baseString);
  const mySignature = `v0=${hmac.digest('hex')}`;

  if (!crypto.timingSafeEqual(Buffer.from(mySignature), Buffer.from(slackSignature))) {
    throw new Error('Slack signature verification failed.');
  }
}

// --- NEW: Helper Function to Create a Meet Link ---
async function createGoogleMeet(text) {
  // 1. Get credentials from Netlify environment
  const calendarId = process.env.CALENDAR_ID;
  const credsBase64 = process.env.GCP_CREDS_BASE64;

  if (!calendarId || !credsBase64) {
    throw new Error('Server config error: Missing CALENDAR_ID or GCP_CREDS_BASE64');
  }

  // 2. Decode the Base64 key
  const decodedKey = Buffer.from(credsBase64, 'base64').toString('utf8');
  const credentials = JSON.parse(decodedKey);

  // 3. Authenticate our "robot"
  const auth = new google.auth.JWT(
    credentials.client_email,
    null,
    credentials.private_key,
    ['https://www.googleapis.com/auth/calendar.events']
  );

  const calendar = google.calendar({ version: 'v3', auth });

  // 4. Create a calendar event for right now
  const eventStartTime = new Date();
  const eventEndTime = new Date();
  eventEndTime.setMinutes(eventStartTime.getMinutes() + 60); // 1-hour meeting

  const event = {
    summary: text || 'New Slack Meeting',
    description: 'Meeting created by the Slack /googlemeet command.',
    start: {
      dateTime: eventStartTime.toISOString(),
      timeZone: 'UTC',
    },
    end: {
      dateTime: eventEndTime.toISOString(),
      timeZone: 'UTC',
    },
    // This is the magic part that creates the Meet link
    conferenceData: {
      createRequest: {
        requestId: `slack-meet-${Date.now()}`,
        conferenceSolutionKey: {
          type: 'hangoutsMeet',
        },
      },
    },
  };

  // 5. Insert the event into our "Slack Bot Meetings" calendar
  const res = await calendar.events.insert({
    calendarId: calendarId,
    resource: event,
    conferenceDataVersion: 1,
  });

  // 6. Return the new meeting link
  return res.data.hangoutLink;
}

// --- Main Function Handler ---
exports.handler = async (event) => {
  try {
    // 1. Verify the request is from Slack (Security First!)
    verifyRequest(event);

  } catch (error) {
    console.warn('Slack verification failed:', error.message);
    return { statusCode: 403, body: 'Slack signature verification failed.' };
  }

  try {
    // 2. Parse Slack data
    const params = new URLSearchParams(event.body);
    const userName = params.get('user_name') || 'there';
    const text = params.get('text'); // "Team Meeting"

    //
    // 3. NEW: Call the Google API to create a unique link
    //
    const meetLink = await createGoogleMeet(text);

    // 4. Create the Slack message
    let messageText = `Here's your new Google Meet link:`;
    if (text) {
      messageText = `Here's the Google Meet link for: *${text}*`;
    }
    
    const slackResponse = {
      response_type: 'in_channel',
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: messageText,
          },
        },
        {
          type: 'actions',
          elements: [
            {
              type: 'button',
              text: {
                type: 'plain_text',
                text: 'Join Meeting',
                emoji: true,
              },
              url: meetLink, // <-- Use the new dynamic link
              style: 'primary',
              accessibility_label: 'Button to join the Google Meet call',
            },
          ],
        },
      ],
    };

    // 5. Send the JSON response back to Slack
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(slackResponse),
    };

  } catch (error) {
    console.error('Error in main handler:', error);
    // Send a user-facing error message back to Slack
    return {
      statusCode: 200, // Slack needs a 200, even for an error
      body: JSON.stringify({
        response_type: 'ephemeral',
        text: `Sorry, I couldn't create a meeting. Error: ${error.message}`,
      }),
    };
  }
};