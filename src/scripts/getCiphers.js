const nodeCrypto = require('crypto');
const fs = require('fs');
const path = require('path');
const ciphers = nodeCrypto.getCiphers();

function writeCiphersToFile(ciphers) {
    let outputPath = path.resolve(__dirname, '../output/supported_ciphers_list.txt');
    let outputDir = path.dirname(outputPath);
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }
    fs.writeFileSync(outputPath, ciphers.join('\n'), 'utf8');
    console.log(`Ciphers written to ${outputPath}`);
}
writeCiphersToFile(ciphers);
