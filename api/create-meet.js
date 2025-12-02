/**
 * GOOGLE MEET SLACK BOT (Rollback / Standard Version)
 * ---------------------------------------------------
 * - Uses standard "in_channel" response.
 * - Does NOT require "chat:write" permission (Works without Admin approval).
 * - Command text (/meet) remains visible in history.
 */

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

// --- LOGIC: Generate Link ---
function generateLink(text) {
  let baseName = "instant-meeting";

  // Use custom title if provided
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

  // Audit Log
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
    
    // Handle Button Clicks (Prevent warning triangle)
    if (params.get('payload')) return response.status(200).send('');

    const text = params.get('text');

    // Generate Link
    const meetLink = generateLink(text);

    // Return response directly to Slack
    // This works purely based on the slash command trigger, no extra permissions needed.
    return response.status(200).json({
      response_type: 'in_channel',
      blocks: [
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