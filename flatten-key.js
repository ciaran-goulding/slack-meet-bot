const fs = require('fs');
const path = require('path');

// This matches the file you moved earlier
const fileName = 'google-key.json';
const filePath = path.join(__dirname, fileName);

try {
  // Read the file
  const fileContent = fs.readFileSync(filePath, 'utf8');
  
  // Parse it to JSON, then Stringify it back to a single line
  const jsonObject = JSON.parse(fileContent);
  const flatString = JSON.stringify(jsonObject);
  
  console.log('\n✅ SUCCESS! Copy the RAW JSON string below:');
  console.log('---------------------------------------------------');
  console.log(flatString);
  console.log('---------------------------------------------------');
} catch (err) {
  console.error('Error:', err.message);
}