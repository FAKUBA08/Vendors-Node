const mongoose = require('mongoose');

// Define the Seller schema
const sellerSchema = new mongoose.Schema({
  marketplaceName: { type: String, required: true },
  subdomain: { type: String, required: true ,unique:true},
  storeInformation: { type: String, required: true },
  storeAddress: {
    country: { type: String, required: true },
    state: { type: String, required: true },
    city: { type: String, required: true },
    street: { type: String },
    zipCode: { type: String }
  }
}, { timestamps: true });


const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
    minlength: [8, 'Password must be at least 8 characters long'],
  },
  phoneNumber: {
    type: String,
    required: true,
    unique: [true, 'Phone number has been used'],
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  isVerified: { type: Boolean, default: false },
  setupComplete: { type: Boolean, default: false },
  
  seller: sellerSchema,  
  
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
