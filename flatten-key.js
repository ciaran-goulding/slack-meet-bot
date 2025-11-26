const fs = require('fs');
const path = require('path');

// Your key file name
const fileName = 'google-key.json';
const inputPath = path.join(__dirname, fileName);
const outputPath = path.join(__dirname, 'vercel-secret.txt');

try {
  const fileContent = fs.readFileSync(inputPath, 'utf8');
  const jsonObject = JSON.parse(fileContent);
  const flatString = JSON.stringify(jsonObject);
  
  // Write to a file so nothing gets cut off
  fs.writeFileSync(outputPath, flatString);
  
  console.log('\n✅ SUCCESS!');
  console.log(`I have saved the long secret string to this file:`);
  console.log(`👉 ${outputPath}`);
  console.log('\n1. Open that file in Notepad.');
  console.log('2. Select All (Ctrl+A) and Copy (Ctrl+C).');
  console.log('3. Paste that into Vercel.');
} catch (err) {
  console.error('Error:', err.message);
}