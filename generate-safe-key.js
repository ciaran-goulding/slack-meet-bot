const fs = require('fs');
const path = require('path');

// Read your working JSON file
const keyPath = path.join(__dirname, 'google-key.json');

try {
  const fileContent = fs.readFileSync(keyPath, 'utf8');
  const credentials = JSON.parse(fileContent);

  // Get the private key and Base64 encode it
  // This turns newlines into safe letters like "Cg=="
  const privateKey = credentials.private_key;
  const safeString = Buffer.from(privateKey).toString('base64');

  console.log('\n✅ COPY THE STRING BELOW (It is safe for Vercel):');
  console.log('---------------------------------------------------');
  console.log(safeString);
  console.log('---------------------------------------------------');
  console.log('Variable Name: GOOGLE_PRIVATE_KEY');

} catch (err) {
  console.error('Error:', err.message);
}