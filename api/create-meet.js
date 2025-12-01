/**
 * GOOGLE MEET SLACK BOT (Hybrid Naming Version)
 * ---------------------------------------------
 * Features:
 * 1. Custom Links: Uses user input if provided (e.g. project-alpha-xxxx).
 * 2. Instant Links: Defaults to 'instant-meeting-xxxx' if input is empty.
 * 3. Security: No Slack User Data lookup (Zero permissions required).
 * 4. Audit: Logs activity to System Console.
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

// --- CORE LOGIC: Generate Hybrid Link ---
function generateLink(text, userId) {
  let baseName = "instant-meeting";

  // LOGIC: If user typed something, use it. Otherwise keep default.
  if (text && text.trim().length > 0) {
    baseName = text.toLowerCase()
      .replace(/['’]/g, '')       // Remove apostrophes
      .replace(/\s+/g, '-')       // Replace spaces with hyphens
      .replace(/[^a-z0-9-]/g, '') // Remove special chars
      .replace(/-+/g, '-');       // Cleanup double hyphens
  }

  // Generate a massive random number (9 digits) to ensure uniqueness
  // This prevents collision even if two teams type "/meet Project X"
  const randomCode = Math.floor(100000000 + Math.random() * 900000000);
  
  // Format: project-alpha-928374651
  const slug = `${baseName}-${randomCode}`;
  const meetLink = `https://meet.google.com/lookup/${slug}`;

  // --- SECURITY AUDIT LOG ---
  console.log(JSON.stringify({
    event: "MEETING_CREATED",
    requester_id: userId,
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
    const userId = params.get('user_id');

    // Generate the link based on user input
    const meetLink = generateLink(text, userId);

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