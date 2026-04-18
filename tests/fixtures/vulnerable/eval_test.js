// aiscan test fixture — should trigger AI-SEC-009 JS (Eval/Exec)
// DO NOT USE IN PRODUCTION

const userInput = req.body.code;

// Unsafe: eval on user input
const result = eval(userInput);

// Unsafe: new Function from user input
const fn = new Function('return ' + userInput);
