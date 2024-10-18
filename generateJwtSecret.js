const crypto = require('crypto');

// Function to generate a JWT secret
const generateJwtSecret = () => {
    const secret = crypto.randomBytes(64).toString('hex');
    console.log('Generated JWT Secret:', secret);
};

// Call the function
generateJwtSecret();
