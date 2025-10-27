// This 'crypto' library is built into Node.js, so no 'npm install' is needed.
const crypto = require('crypto');

exports.handler = async (event) => {
  // --- 1. Security: Verify the request is from Slack ---
  
  // Get the Slack signing secret from your Netlify environment variables
  const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
  if (!slackSigningSecret) {
    console.error('SLACK_SIGNING_SECRET is not set in environment variables.');
    return { statusCode: 500, body: 'Server configuration error.' };
  }

  // Get the signature and timestamp from the request headers
  const timestamp = event.headers['x-slack-request-timestamp'];
  const slackSignature = event.headers['x-slack-signature'];
  const requestBody = event.body; // This is the raw string body

  // Check for replay attacks: timestamp must be < 5 minutes old
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
  if (timestamp < fiveMinutesAgo) {
    console.warn('Old timestamp received. Ignoring request.');
    return { statusCode: 403, body: 'Request timestamp is too old.' };
  }

  // Create the 'basestring' to sign
  const baseString = `v0:${timestamp}:${requestBody}`;

  // Create our own signature using the secret
  const hmac = crypto.createHmac('sha256', slackSigningSecret);
  hmac.update(baseString);
  const mySignature = `v0=${hmac.digest('hex')}`;

  // Compare our signature with Slack's using a timing-safe method
  try {
    if (!crypto.timingSafeEqual(Buffer.from(mySignature), Buffer.from(slackSignature))) {
      console.warn('Signature verification failed.');
      return { statusCode: 403, body: 'Slack signature verification failed.' };
    }
  } catch (e) {
     console.warn('Error during signature comparison:', e.message);
     return { statusCode: 403, body: 'Slack signature verification failed.' };
  }
  
  // --- 2. Main Logic: Create and Send the Meet Link ---
  // If we reach here, the request is verified!

  try {
    // Parse the incoming Slack data (it's URL-encoded)
    const params = new URLSearchParams(requestBody);
    const userName = params.get('user_name') || 'there';
    // This 'text' is any text typed after the /meet command
    const text = params.get('text'); 

    // This link auto-generates a new, unique meeting
    const meetLink = "https://meet.google.com/new";

    // Customize the message text
    let messageText = `A new meeting for *${text}* was started by @${userName}!`;
    if (text) {
      // Use the text from the command as a meeting title
      messageText = `Here's the Google Meet link for: *${text}*`;
    }

    // This is the JSON payload we send back to Slack
    const slackResponse = {
      // 
      // THIS IS THE KEY CHANGE: Makes the message visible to everyone
      //
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
              url: meetLink, 
              style: 'primary', // Makes the button green
              accessibility_label: 'Button to join the Google Meet call',
            },
          ],
        },
      ],
    };

    // 5. Send the JSON response back to Slack
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(slackResponse),
    };

  } catch (error) {
    console.error('Error processing Slack command:', error);
    return {
      statusCode: 500,
      body: 'Something went wrong while processing your request.',
    };
  }
};