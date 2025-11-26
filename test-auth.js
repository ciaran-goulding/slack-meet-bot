const { google } = require('googleapis');
const fs = require('fs');
const path = require('path');

const keyPath = path.join(__dirname, 'google-key.json');

async function testAuth() {
  console.log('Reading key file...');
  try {
    const fileContent = fs.readFileSync(keyPath, 'utf8');
    const credentials = JSON.parse(fileContent);

    // 1. Fix newlines (Crucial step)
    // This handles cases where the key has literal "\n" characters
    if (credentials.private_key && credentials.private_key.includes('\\n')) {
      console.log('Fixing newlines in private_key...');
      credentials.private_key = credentials.private_key.replace(/\\n/g, '\n');
    }

    console.log('Attempting authentication via GoogleAuth...');

    // 2. Use GoogleAuth (Robuster method)
    const auth = new google.auth.GoogleAuth({
      credentials: credentials, // Pass the whole object
      scopes: ['https://www.googleapis.com/auth/calendar.events'],
    });

    // 3. Test the connection
    const client = await auth.getClient();
    const token = await client.getAccessToken();
    
    console.log('\n✅ SUCCESS! Google accepted the key.');
    console.log('   Access Token generated successfully.');

  } catch (err) {
    console.error('\n❌ ERROR:', err.message);
    if (err.response) {
        console.error('   Response:', err.response.data);
    }
  }
}

testAuth();