
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const authRoutes = require('./routes/auth');



dotenv.config();
const app = express();


app.use(express.json());
const cors = require('cors');

app.use(cors({
    origin: 'https://vendors-node.vercel.app',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true, 
}));


mongoose.connect(process.env.MONGO_URI,)
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.error("MongoDB connection error: ", err));


app.use('/api/auth', authRoutes);


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
