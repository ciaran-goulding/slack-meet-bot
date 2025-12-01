/**
 * GOOGLE MEET SLACK BOT (SecOps Approved Version)
 * -----------------------------------------------
 * Features:
 * 1. Generates anonymized "Lookup" links (instant-meeting-xxxx).
 * 2. No PII (Personally Identifiable Information) in URLs.
 * 3. No Slack User Data lookup (Zero-Knowledge).
 * 4. Logs audit trail to System Console.
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

// --- CORE LOGIC: Generate Anonymized Link ---
function generateLink(userId) {
  // REQUIREMENT: All meetings labelled as 'instant-meeting-xxxx'
  // We use a large random number to ensure no collisions across 8000 users.
  // Using 9 digits ensures millions of unique combinations.
  const randomCode = Math.floor(100000000 + Math.random() * 900000000);
  const slug = `instant-meeting-${randomCode}`;

  // The Lookup Link
  const meetLink = `https://meet.google.com/lookup/${slug}`;

  // --- SECURITY AUDIT LOG ---
  // We log the User ID (U12345) internally for audit, but not in the URL.
  console.log(JSON.stringify({
    event: "MEETING_CREATED",
    requester_id: userId,
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
    
    // Handle Button Clicks (Stop Warning Triangle)
    if (params.get('payload')) return response.status(200).send('');

    // We no longer need 'text' or 'user_name' for the logic
    const userId = params.get('user_id');

    // Generate the standardized link
    const meetLink = generateLink(userId);

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