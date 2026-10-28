//const path = require('path');
require('dotenv').config();
const express = require('express');
const fileUpload = require('express-fileupload');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const userRoute = require('./routes/userRoute');
const errorHandler = require('./middleware/errorMiddleware');
const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');
const xss = require('xss-clean');

const app = express();

// For CommonJS (require)
const dns = require('node:dns');
dns.setServers(['8.8.8.8', '1.1.1.1']);

// Middlewares
app.use(express.json());
app.use(fileUpload());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(
  cors({
    origin: ['http://localhost:3000', 'https://authz-app-nu.vercel.app'],
    credentials: true
  })
);
app.listen(5000, () => {
  console.log(`Server is running on ${PORT}`);
});

// Add the parent origin to the frame-ancestors directive
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      "frame-ancestors": ["'self'", "http://localhost:5000", "http://localhost:3000"],
    },
  })
);

app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use('/files', express.static('files'));

// Sanitize data
app.use(mongoSanitize());

// set security headers
app.use(helmet());

// Prevent XSS attacks, make sure this comes before any routes
app.use(xss());

// Routes
app.use('/api/users', userRoute);

app.get('/', (req, res) => {
  res.send('Home Page');
});

app.get('/api/uploadfiles', async (req, res) => {
  res.send('Success!!!');
});

app.post('/upload', (req, res) => {
  // We'll handle the image upload here
});

// error handler
app.use(errorHandler);

const PORT = process.env.PORT || 5000;
// Connect to Local MongoDB
// mongoose
//   .connect('mongodb://0.0.0.0:27017/mern-music')

//   .then(() => {
//     console.log(`MongoDb Server running on ${PORT}`);
//   })
//   .catch(() => {
//     console.log('Local MongoDb failed');
//   });

const connectDB = async () => {
  try {
    // Replace with a valid SRV URI
    const conn = await mongoose.connect("mongodb+srv://jhungulle_db_user:yiGmfYoi076H1GNg@cluster0.lzrgnja.mongodb.net/reservist-db?appName=Cluster0");
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('MongoDB connection failed:', error.message);
    process.exit(1);
  }
};
connectDB();
