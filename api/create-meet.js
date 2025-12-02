/**
 * GOOGLE MEET SLACK BOT (Stealth Mode)
 * ------------------------------------
 * Update: Now uses 'chat.postMessage' to send the link.
 * This keeps the original "/meet" command PRIVATE (invisible to channel),
 * but the resulting "Join" button PUBLIC.
 */

import crypto from 'crypto';

export const config = {
  api: { bodyParser: false },
};

// --- HELPER: Read Raw Request Body ---
async function getRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString();
}

// --- HELPER: Verify Slack Security Signature ---
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

// --- HELPER: Post Message to Slack (The Stealth Method) ---
async function postToSlack(channelId, blocks) {
  const token = process.env.SLACK_BOT_TOKEN;
  if (!token) throw new Error("Missing SLACK_BOT_TOKEN");

  const response = await fetch('https://slack.com/api/chat.postMessage', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      channel: channelId,
      blocks: blocks,
      text: "New Google Meet Link" // Fallback text for notifications
    })
  });

  const data = await response.json();
  if (!data.ok) {
    console.error("Slack API Error:", data.error);
  }
}

// --- LOGIC: Generate Link ---
function generateLink(text) {
  let baseName = "instant-meeting";

  if (text && text.trim().length > 0) {
    baseName = text.toLowerCase()
      .replace(/['’]/g, '')       
      .replace(/\s+/g, '-')       
      .replace(/[^a-z0-9-]/g, '') 
      .replace(/-+/g, '-');       
  }

  const randomCode = Math.floor(100000000 + Math.random() * 900000000);
  const slug = `${baseName}-${randomCode}`;
  const meetLink = `https://meet.google.com/lookup/${slug}`;

  // Log for audit
  console.log(JSON.stringify({
    event: "MEETING_CREATED",
    input_text: text || "(empty)",
    generated_slug: slug,
    timestamp: new Date().toISOString()
  }));

  return meetLink;
}

// --- MAIN HANDLER ---
export default async (request, response) => {
  if (request.method !== 'POST') return response.status(405).send('Method Not Allowed');

  try {
    const rawBody = await getRawBody(request);
    verifyRequest(request.headers, rawBody);

    const params = new URLSearchParams(rawBody);
    
    // Handle Button Clicks
    if (params.get('payload')) return response.status(200).send('');

    const text = params.get('text');
    const channelId = params.get('channel_id'); // We need this to know where to post

    // 1. Generate the Link
    const meetLink = generateLink(text);

    // 2. Define the UI Card
    const blocks = [
      {
        type: "section",
        text: { type: "mrkdwn", text: "Click below to join:" }
      },
      {
        type: "actions",
        elements: [
          {
            type: "button",
            text: { type: "plain_text", text: "Join Meeting", emoji: true },
            url: meetLink,
            style: "primary",
            action_id: "join_button"
          }
        ]
      }
    ];

    // 3. Post the message independently (This keeps the slash command hidden)
    await postToSlack(channelId, blocks);

    // 4. Return an empty 200 OK to Slack
    // This tells Slack "Command received, don't show anything to the user."
    return response.status(200).send('');

  } catch (error) {
    console.error('Handler Error:', error);
    // If it fails, we send an ephemeral message so the user knows
    return response.status(200).json({
      response_type: 'ephemeral',
      text: `⚠️ Error: ${error.message}`,
    });
  }
};