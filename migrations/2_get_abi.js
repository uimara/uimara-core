const fs = require('fs');
const contract = JSON.parse(fs.readFileSync('../build/contracts/Uimara.json', 'utf8'));
abi = JSON.stringify(contract.abi);
console.log(abi);
fs.writeFileSync('../build/Uimara.abi', abi);
