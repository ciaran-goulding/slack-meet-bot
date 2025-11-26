const fs = require('fs');
const path = require('path');

// We renamed the file to be simple
const fileName = 'google-key.json';

// Look in the CURRENT folder (where this script is)
const filePath = path.join(__dirname, fileName);

try {
  console.log(`Looking for file at: ${filePath}`);
  const fileBuffer = fs.readFileSync(filePath);
  const base64String = fileBuffer.toString('base64');
  
  console.log('\nSUCCESS! Copy the string below (between the lines):');
  console.log('---------------------------------------------------');
  console.log(base64String);
  console.log('---------------------------------------------------');
} catch (err) {
  console.error('\nERROR: Still cannot find the file.');
  console.error('Make sure "google-key.json" is in the "slack-meet-bot" folder.');
  console.error('System Error:', err.message);
}