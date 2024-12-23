    const express = require('express');
    const bcrypt = require('bcryptjs');
    const jwt = require('jsonwebtoken');
    const crypto = require('crypto'); 
    const User = require('../models/user');
    const { sendEmail } = require('../emailService'); 

    const router = express.Router();
    // Sign up route
    router.post('/signup', async (req, res) => {
    const { firstName, lastName, email, password, phoneNumber } = req.body;

    if (!password) {
    return res.status(400).json({ message: 'Password is required' });
    }

    if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }

    try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
    firstName,
    lastName,
    email,
    password: hashedPassword,
    phoneNumber,
    isVerified: false, 
    setupComplete: false,
    });

    await newUser.save();

    const verificationToken = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '30min' });

    const subject = 'Verify Your Email';
    const message = `Please click the following link to verify your email: https://vendors-node.onrender.com/api/auth/verify?token=${verificationToken}\nIf you did not sign up for this account, please ignore this email.`;

    await sendEmail({ email: newUser.email, subject, message });

    res.status(201).json({ message: 'User created successfully. Please check your email for verification.' });
    } catch (error) {
    console.error('Error creating user:', error);
    if (error.code === 11000) { // Duplicate key error
    return res.status(400).json({ message: 'The provided email address or phone number is already associated with an existing account.' });

    }
    res.status(500).json({ message: 'Error creating user', error: error.message });
    }
    });


    router.get('/verify', async (req, res) => {
    const { token } = req.query;

    try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id);
    if (!user) {
    return res.status(400).json({ message: 'Invalid token or user not found' });
    }

    user.isVerified = true; 
    await user.save();

    return res.redirect(`https://vendor-s-project.vercel.app/home?message=${encodeURIComponent('Email verified successfully')}`);
    } catch (error) {
    console.error('Error during email verification:', error);
    res.status(500).json({ message: 'Server error during verification' });
    }
    });




    router.post('/resend-verification', async (req, res) => {
    const { email } = req.body;

    try {
    const user = await User.findOne({ email });
    if (!user) {
    return res.status(404).json({ message: 'User not found' });
    }

    if (user.isVerified) {
    return res.status(400).json({ message: 'User is already verified' });
    }

    const verificationToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30min' });

    const subject = 'Resend Verification Email';
    const message = `Please click the following link to verify your email: https://vendors-node.onrender.com/api/auth/verify?token=${verificationToken}\nIf you did not sign up for this account, please ignore this email.`;

    await sendEmail({ email: user.email, subject, message });

    res.status(200).json({ message: 'Verification email resent successfully!' });
    } catch (error) {
    console.error('Error resending verification email:', error);
    res.status(500).json({ message: 'Error resending verification email', error: error.message });
    }
    });

    // Login route
    router.post('/login', async (req, res) => {
        const { email, password } = req.body;
    
        try {
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(400).json({ message: 'Invalid credentials' });
            }
    
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(400).json({ message: 'Invalid credentials' });
            }
    
            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1day' });
    
            res.status(200).json({
                message: 'Login successful',
                token,
                user: {
                    _id: user._id, 
                    firstName: user.firstName,
                    lastName: user.lastName,
                    email: user.email,
                    isVerified: user.isVerified,
                    setupComplete: user.setupComplete,
                }
            });
    
            console.log(`User logged in: ${user.firstName} ${user.lastName}`);
        } catch (error) {
            console.error('Error during login:', error);
            res.status(500).json({ message: 'Server error' });
        }
    });
    

    // Middleware for token authentication
    const authenticateToken = (req, res, next) => {
        const clickResent=`https://vendor-s-project.vercel.app/login/`
        const token = req.headers['authorization']?.split(' ')[1];
    
        if (!token) return res.sendStatus(401);
    

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                console.error('Token verification error:', err);

                if (err.name === 'TokenExpiredError') {
                    return res.status(403).json({ message: `Token expired.${clickResent} Please log in again.` });
                }
    
                return res.sendStatus(403);
            }

            req.user = user;
            next();
        });
    };
    
    

    // Profile route
    router.get('/profile', authenticateToken, async (req, res) => {
        try {
            const user = await User.findById(req.user.id).select('email firstName lastName phoneNumber country state');
    
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
            res.status(200).json({
                message: 'Profile data',
                userId: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                phoneNumber: user.phoneNumber,
                country: user.country,
                state: user.state
            });
        } catch (error) {
            console.error("Error retrieving profile:", error);
            res.status(500).json({ message: 'Server error' });
        }
    });
 

    router.put('/profile', authenticateToken, async (req, res) => {
        try {
          const { email, firstName, lastName, phoneNumber } = req.body;
          const userId = req.user.id;
      
          const updatedUser = await User.updateOne({ _id: userId }, { email, firstName, lastName, phoneNumber });
      
          res.status(200).json({ message: 'Profile updated successfully', updatedUser });
        } catch (error) {
          res.status(500).json({ message: 'Failed to update profile' });
        }
      });
      
    // Forgot password route
    router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
    const user = await User.findOne({ email });
    if (!user) {
    return res.status(404).json({ message: 'No user found with that email address' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.resetPasswordExpire = Date.now() + 30 * 60 * 1000; 

    await user.save();
    const resetUrl = `https://vendor-s-project.vercel.app/reset-password/${resetToken}`;
    console.log('Reset URL:', resetUrl);

    const message = `You requested a password reset. Please click the link below to reset your password:\n${resetUrl}\nIf you did not request this, please ignore this email.`;

    await sendEmail({ email: user.email, subject: 'Password Reset Request', message });

    res.status(200).json({ message: 'Password reset link sent to email' });
    } catch (error) {
    console.error('Error during password reset:', error);
    res.status(500).json({ message: 'Server error' });
    }
    });



    router.get('/reset-password/:resetToken', (req, res) => {
    res.send('Please enter your new password.'); 
    });

    router.post('/reset-password/:resetToken', async (req, res) => {
    const { resetToken } = req.params;
    const { newPassword } = req.body;

    try {
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    const user = await User.findOne({
    resetPasswordToken: hashedToken,
    resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
    return res.status(400).json({ message: 'Invalid or expired token' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = undefined; 
    user.resetPasswordExpire = undefined;

    await user.save();
    if(user.password<8){
    return res.status(400).json({message:"password must be at least 8 characters"})
    }
    res.status(200).json({ message: 'Password has been reset successfully' });
    } catch (error) {
    console.error('Error during password reset:', error);
    res.status(500).json({ message: 'Server error' }); 
    }
    });


    router.post('/saveSeller', authenticateToken, async (req, res) => {
        const { marketplaceName, subdomain, storeInformation, storeAddress } = req.body;
        const { country, state, city } = storeAddress;
    
        console.log('Received store address:', storeAddress);
        const userId = req.user?.id;
    
        try {
            if (!userId) {
                return res.status(401).json({ message: 'Unauthorized: User ID not found' });
            }
    
            const user = await User.findById(userId);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
    
            user.seller = {
                marketplaceName,
                subdomain,
                storeInformation,
                storeAddress,
                country,
                state,
                city
            };
            
            user.setupComplete = true;
            await user.save();
    
            res.status(201).json({ message: 'Seller details saved successfully', setupComplete: user.setupComplete });
        } catch (error) {
            console.error('Error saving seller details:', error);
            res.status(500).json({ message: 'Error saving seller details', error: error.message });
        }
    });
    
    router.get('/setupComplete', authenticateToken, async (req, res) => {
        try {
            const user = await User.findById(req.user.id);
            
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
    
            const setupComplete = !!user.seller; 
            res.status(200).json({ setupComplete });
        } catch (error) {
            console.error('Error checking setup complete status:', error);
            res.status(500).json({ message: 'Error checking setup complete status', error: error.message });
        }
    });



    router.get('/subdomain', authenticateToken, async (req, res) => {
        const userId = req.user?.id;
    
        try {
            const user = await User.findById(userId);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
    
            const { subdomain } = user.seller || {};
            res.status(200).json({ subdomain, setupComplete: user.setupComplete });
        } catch (error) {
            console.error('Error fetching subdomain:', error);
            res.status(500).json({ message: 'Error fetching subdomain', error: error.message });
        }
    });
    module.exports = router;