/**
 * GOOGLE MEET SLACK BOT (Lightweight Version)
 * -------------------------------------------
 * Features:
 * 1. Generates unique "Lookup" links (No Google API required).
 * 2. Fetches user names from Slack for clean URLs.
 * 3. Logs activity to System Console (Stdout) for Security Auditing.
 * 4. Zero Google Credentials required.
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

// --- HELPER: Fetch User's Real Name ---
async function getSlackName(userId) {
  const token = process.env.SLACK_BOT_TOKEN;
  if (!token) return null;

  try {
    const params = new URLSearchParams({ user: userId });
    const response = await fetch(`https://slack.com/api/users.info?${params}`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });

    const data = await response.json();
    if (data.ok && data.user) return data.user.profile.real_name;
  } catch (error) {
    console.error("Slack Lookup Error:", error.message);
  }
  return null;
}

// --- CORE LOGIC: Generate Link (No API) ---
async function generateLink(text, userId, defaultHandle) {
  let rawTitle;
  let suffix = "";
  
  if (text && text.trim().length > 0) {
    // User typed a title
    rawTitle = text;
  } else {
    // Instant Meeting: Use Name + Random Code
    const realName = await getSlackName(userId);
    const displayName = realName || defaultHandle;
    const randomCode = Math.floor(1000 + Math.random() * 9000);
    
    rawTitle = `${displayName}'s meeting`; 
    suffix = `-${randomCode}`;
  }

  // Sanitize for URL
  const cleanSlug = rawTitle.toLowerCase()
    .replace(/['’]/g, '')       // Remove apostrophes
    .replace(/\s+/g, '-')       // Spaces to hyphens
    .replace(/[^a-z0-9-]/g, '') // Remove special chars
    .replace(/-+/g, '-');       // Cleanup

  const meetLink = `https://meet.google.com/lookup/${cleanSlug}${suffix}`;

  // --- SECURITY AUDIT LOG ---
  // This prints to Vercel/AWS CloudWatch logs for your SecOps team.
  console.log(JSON.stringify({
    event: "MEETING_CREATED",
    user_id: userId,
    handle: defaultHandle,
    input_text: text,
    generated_link: meetLink,
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
    
    // Handle Button Clicks (Stop Warning Triangle)
    if (params.get('payload')) return response.status(200).send('');

    const text = params.get('text');
    const userId = params.get('user_id');
    const handle = params.get('user_name');

    const meetLink = await generateLink(text, userId, handle);

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