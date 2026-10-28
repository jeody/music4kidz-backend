const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');
const Token = require('../models/tokenModel');
const bcrypt = require('bcryptjs');
const { generateToken, hashToken } = require('../utils');
var parser = require('ua-parser-js');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');
const sendPdfEmail = require('../utils/sendPdfEmail');
const imageValidate = require('../utils/imageValidate');
const crypto = require('crypto');
const Cryptr = require('cryptr');
const permitValidate = require('../utils/permitValidate');
const { OAuth2Client } = require('google-auth-library');
const { log } = require('console');

const cryptr = new Cryptr(process.env.CRYPTR_KEY);

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

// Register User
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  // Validation
  if (!name || !email || !password) {
    res.status(400);
    throw new Error('Please fill in all the required fields.');
  }

  if (password.length < 8) {
    res.status(400);
    throw new Error('Password must be up to 6 characters.');
  }

  // Check if user exists
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error('Email already in use.');
  }

  // Get UserAgent
  const ua = parser(req.headers['user-agent']);
  const userAgent = [ua.ua];

  //   Create new user
  const user = await User.create({
    name,
    email,
    password,
    userAgent
  });

  // Generate Token
  const token = generateToken(user._id);

  // Send HTTP-only cookie
  res.cookie('token', token, {
    path: '/',
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: 'none',
    secure: true
  });

  if (user) {
    const {
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      permitUploaded,
      formSet
    } = user;

    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
      permitUploaded,
      formSet
    });
  } else {
    res.status(400);
    throw new Error('Invalid user data');
  }
});

// Login User
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  //   Validation
  if (!email || !password) {
    res.status(400);
    throw new Error('Please add email and password');
  }

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error('User not found, please signup');
  }

  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  if (!passwordIsCorrect) {
    res.status(400);
    throw new Error('Invalid email or password');
  }

  // Trgger 2FA for unknow UserAgent
  const ua = parser(req.headers['user-agent']);
  const thisUserAgent = ua.ua;
  console.log(thisUserAgent);
  const allowedAgent = user.userAgent.includes(thisUserAgent);

  if (!allowedAgent) {
    // Genrate 6 digit code
    const loginCode = Math.floor(100000 + Math.random() * 900000);
    console.log(loginCode);

    // Encrypt login code before saving to DB
    const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

    // Delete Token if it exists in DB
    let userToken = await Token.findOne({ userId: user._id });
    if (userToken) {
      await userToken.deleteOne();
    }

    // Save Token to DB
    await new Token({
      userId: user._id,
      loginToken: encryptedLoginCode,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * (60 * 1000) // 60mins
    }).save();

    res.status(400);
    throw new Error('New browser or device detected');
  }

  // Check if user is verified
  const unverifiedUser = user.isVerified;

  if (!unverifiedUser) {
    res.status(400);
    throw new Error('Unverified Account: Please check your email to continue!');    
  }
  
  // Trigger 2FA by sending login code/OTP to email
  const verifiedUser = user.isVerified;
  if (verifiedUser) {

     // Genrate 6 digit code
    const otp = Math.floor(100000 + Math.random() * 900000);
    console.log(otp);

    // Encrypt otp code before saving to DB
    const encryptedOtp = cryptr.encrypt(otp.toString());

    // Delete Token if it exists in DB
    let userToken = await Token.findOne({ userId: user._id });
    if (userToken) {
      await userToken.deleteOne();
    }

    // Save otp Token to DB
    await new Token({
      userId: user._id,
      otp: encryptedOtp,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
    }).save();

    res.status(400);
    throw new Error('OTP required: Please check your email to continue');
  }
  // Trigger 2FA by sending login code/OTP to email

  // Generate Token
  const token = generateToken(user._id);

  if (user && passwordIsCorrect) {
    // Send HTTP-only cookie
    res.cookie('token', token, {
      path: '/',
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: 'none',
      secure: true
    });

    const {
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      permitUploaded,
      role,
      isVerified,
      formSet
    } = user;

    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      permitUploaded,
      role,
      isVerified,
      // token,
      formSet
    });
  } else {
    res.status(500);
    throw new Error('Something went wrong, please try again');
  }
});

// Send Login Code
const sendLoginCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  // Find Login Code in DB
  let userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() }
  });

  if (!userToken) {
    res.status(404);
    throw new Error('Invalid or Expired token, please login again');
  }

  const loginCode = userToken.loginToken;
  const decryptedLoginCode = cryptr.decrypt(loginCode);

  // Send Login Code
  const subject = 'Login Access Code - Music4Kidz';
  const send_to = email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = 'noreply@music4kidz.com';
  const template = 'loginCode';
  const name = user.name;
  const link = decryptedLoginCode;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ message: `Access code sent to ${email}` });
  } catch (error) {
    res.status(500);
    throw new Error('Email not sent, please try again');
  }
});

// Send Otp Code
const sendOtpCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  // Find Login Code in DB
  let userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error('Invalid or Expired OTP, please login again');
  }

  const OtpCode = userToken.otp;
  const decryptedOtpCode = cryptr.decrypt(OtpCode); 

  // Send Otp Code
  const subject = 'One-Time Password - Music4Kidz';
  const send_to = email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = 'noreply@music4kidz.com';
  const template = 'otp';
  const name = user.name;
  const link = decryptedOtpCode;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ message: `OTP sent to ${email}` });
  } catch (error) {
    res.status(500);
    throw new Error('OTP not sent, please try again');
  }
});

// Login With Code
const loginWithCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const { loginCode } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  // Find user Login Token
  const userToken = await Token.findOne({
    userId: user.id,
    expiresAt: { $gt: Date.now() }
  });

  if (!userToken) {
    res.status(404);
    throw new Error('Invalid or Expired Token, please login again');
  }

  const decryptedLoginCode = cryptr.decrypt(userToken.loginToken);

  if (loginCode !== decryptedLoginCode) {
    res.status(400);
    throw new Error('Incorrect login code, please try again');
  } else {
    // Register userAgent
    const ua = parser(req.headers['user-agent']);
    const thisUserAgent = ua.ua;
    user.userAgent.push(thisUserAgent);
    await user.save();

    // Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie('token', token, {
      path: '/',
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: 'none',
      secure: true
    });

    const {
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      permitUploaded,
      role,
      isVerified,
      formSet
    } = user;

    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      permitUploaded,
      role,
      isVerified,
      token,
      formSet
    });
  }
});

// Login With Otp
const loginWithOtp = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const { otpCode } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  // Find user Login Token
  const userToken = await Token.findOne({
    userId: user.id,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error('Invalid or Expired Token, please login again!');
  }

  const decryptedotpCode = cryptr.decrypt(userToken.otp);

  if (otpCode !== decryptedotpCode) {
    res.status(400);
    throw new Error('Incorrect login code, please try again!');
  } else {
  
    // Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie('token', token, {
      path: '/',
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: 'none',
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
});

// Send Verification Email
const sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  if (user.isVerified) {
    res.status(400);
    throw new Error('User already verified');
  }

  // Delete Token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  //   Create Verification Token and Save
  const verificationToken = crypto.randomBytes(32).toString('hex') + user._id;
  console.log(verificationToken);

  // Hash token and save
  const hashedToken = hashToken(verificationToken);
  await new Token({
    userId: user._id,
    verifyToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000) // 60mins
  }).save();

  // Construct Verification URL
  const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

  // Send Email
  const subject = 'Verify Your Account - Music4Kidz';
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = 'noreply@music4kidz.com';
  const template = 'verifyEmail';
  const name = user.name;
  const link = verificationUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ message: 'Verification Email Sent' });
  } catch (error) {
    res.status(500);
    throw new Error('Email not sent, please try again');
  }
});

// Verify User
const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  const hashedToken = hashToken(verificationToken);

  const userToken = await Token.findOne({
    verifyToken: hashedToken,
    expiresAt: { $gt: Date.now() }
  });

  if (!userToken) {
    res.status(404);
    throw new Error('Invalid or Expired Token');
  }

  // Find User
  const user = await User.findOne({ _id: userToken.userId });

  if (user.isVerified) {
    res.status(400);
    throw new Error('User is already verified');
  }

  // Now verify user
  user.isVerified = true;
  await user.save();

  res.status(200).json({ message: 'Account Verification Successful' });
});

// Logout User
const logoutUser = asyncHandler(async (req, res) => {
  res.cookie('token', '', {
    path: '/',
    httpOnly: true,
    expires: new Date(0), // 1 day
    sameSite: 'none',
    secure: true
  });
  return res.status(200).json({ message: 'Logout successful' });
});

const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const {
      _id,
      name,
      email,
      birthdate,
      phone,
      street,
      city,
      cityId,
      country,
      province,
      provinceId,
      region,
      regionId,
      bio,
      photo,
      role,
      isVerified,
      address,
      barangay,
      permit,
      permitUploaded,
      permitApproved,
      approveAbstract,
      approvedVerbal,
      approvedNumerical,
      hasTaken,
      abstractScore,
      abstractItems,
      abstractPercent,
      formSet,
      verbalItems,
      verbalScore,
      verbalPercent,
      numberItems,
      numberScore,
      numberPercent,
      totalScore,
      totalPercent,
      description,
      eligibility,
      grade,
      remarks,
      exam_date,
      next_retake,
      branchOfService,
      purposeOfExam,
      batchCode,
      signatoryId,
      isAddedMember,
      memberId
    } = user;

    res.status(200).json({
      _id,
      name,
      email,
      birthdate,
      phone,
      bio,
      photo,
      street,
      city,
      cityId,
      country,
      role,
      isVerified,
      address,
      barangay,
      province,
      provinceId,
      region,
      regionId,
      permit,
      permitUploaded,
      permitApproved,
      approveAbstract,
      approvedVerbal,
      approvedNumerical,
      hasTaken,
      abstractScore,
      abstractItems,
      abstractPercent,
      formSet,
      verbalItems,
      verbalScore,
      verbalPercent,
      numberItems,
      numberScore,
      numberPercent,
      totalScore,
      totalPercent,
      description,
      eligibility,
      grade,
      remarks,
      exam_date,
      next_retake,
      branchOfService,
      purposeOfExam,
      batchCode,
      signatoryId,
      isAddedMember,
      memberId
    });
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// Update User
const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const {
      name,
      email,
      birthdate,
      phone,
      photo,
      role,
      isVerified,
      street,
      city,
      country,
      branchOfService,
      purposeOfExam,
      signatoryId
    } = user;

    user.email = req.body.email ||email;
    user.name = req.body.name || name;
    user.birthdate = req.body.birthdate || birthdate;
    user.phone = req.body.phone || phone;
    //user.address = req.body.address || address;
    user.photo = req.body.photo || photo;
    user.street = req.body.street || street;
    user.city = req.body.city || city;
    user.country = req.body.country || country;
    user.branchOfService = req.body.branchOfService || branchOfService;
    user.purposeOfExam = req.body.purposeOfExam || purposeOfExam;
    user.hasPurpose = true;
    const updatedUser = await user.save();

    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      birthdate: updatedUser.birthdate,
      phone: updatedUser.phone,
      street: updatedUser.street,
      city: updatedUser.city,
      country: updatedUser.country,
      photo: updatedUser.photo,
      role: updatedUser.role,
      isVerified: updatedUser.isVerified,
      branchOfService: updatedUser.branchOfService,
      purposeOfExam: updatedUser.purposeOfExam,
      hasPurpose: updatedUser.hasPurpose,
      signatoryId: updatedUser.signatoryId
    });
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// Delete User
const deleteUser = asyncHandler(async (req, res) => {
  const user = User.findById(req.params.id);

  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  await user.deleteOne();
  res.status(200).json({
    message: 'User deleted successfully'
  });
});

// Get Users
const getUsers = asyncHandler(async (req, res) => {
  const users = await User.find().sort('-createdAt').select('-password');
  if (!users) {
    res.status(500);
    throw new Error('Something went wrong');
  }
  res.status(200).json(users);
});

// Get Login Status
const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }

  // Verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET);

  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});

const upgradeUser = asyncHandler(async (req, res) => {
  const { role, id } = req.body;

  const user = await User.findById(id);

  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  user.role = role;
  await user.save();

  res.status(200).json({
    message: `User role updated to ${role}`
  });
});

// Send Automated emails
const sendAutomatedEmail = asyncHandler(async (req, res) => {
  const { subject, send_to, reply_to, template, url } = req.body;

  if (!subject || !send_to || !reply_to || !template) {
    res.status(500);
    throw new Error('Missing email parameter');
  }

  // Get user
  const user = await User.findOne({ email: send_to });

  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  const sent_from = process.env.EMAIL_USER;
  const name = user.name;
  const link = `${process.env.FRONTEND_URL}${url}`;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ message: 'Email Sent' });
  } catch (error) {
    res.status(500);
    throw new Error('Email not sent, please try again');
  }
});

// Forgot Password
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error('No user with this email');
  }

  // Delete Token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  //   Create Verification Token and Save
  const resetToken = crypto.randomBytes(32).toString('hex') + user._id;
  console.log(resetToken);

  // Hash token and save
  const hashedToken = hashToken(resetToken);
  await new Token({
    userId: user._id,
    resetToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000) // 60mins
  }).save();

  // Construct Reset URL
  const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

  // Send Email
  const subject = 'Password Reset Request - Music4Kidz';
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = 'noreply@music4kidz.com';
  const template = 'forgotPassword';
  const name = user.name;
  const link = resetUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ message: 'Password Reset Email Sent' });
  } catch (error) {
    res.status(500);
    throw new Error('Email not sent, please try again');
  }
});

// Reset Password
const resetPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;
  console.log(resetToken);
  console.log(password);

  const hashedToken = hashToken(resetToken);

  const userToken = await Token.findOne({
    resetToken: hashedToken,
    expiresAt: { $gt: Date.now() }
  });

  if (!userToken) {
    res.status(404);
    throw new Error('Invalid or Expired Token');
  }

  // Find User
  const user = await User.findOne({ _id: userToken.userId });

  // Now Reset password
  user.password = password;
  await user.save();

  res.status(200).json({ message: 'Password Reset Successful, please login' });
});

// Change Password
const changePassword = asyncHandler(async (req, res) => {
  const { oldPassword, password } = req.body;
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  if (!oldPassword || !password) {
    res.status(400);
    throw new Error('Please enter old and new password');
  }

  // Check if old password is correct
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

  // Save new password
  if (user && passwordIsCorrect) {
    user.password = password;
    await user.save();

    res
      .status(200)
      .json({ message: 'Password change successful, please re-login' });
  } else {
    res.status(400);
    throw new Error('Old password is incorrect');
  }
});

// Change Address
const changeAddress = asyncHandler(async (req, res) => {
  const { street, barangay, city, cityId, province, provinceId, region, regionId } = req.body;
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  const address = `${street}` + (barangay ? `, ${barangay}` : '') + (city ? `, ${city}` : '') + (province ? `, ${province}` : '');

  if (!address) {
    res.status(400);
    throw new Error('Please enter a new address');
  }

  // Save new address
  user.address = address;
  user.street = street;
  user.barangay = barangay;
  user.city = city;
  user.cityId = cityId;
  user.province = province;
  user.provinceId = provinceId;
  user.region = region;
  user.regionId = regionId;
  await user.save();

  res.status(200).json({ message: 'Address change successful' });
});

// Login with Google
const loginWithGoogle = asyncHandler(async (req, res) => {
  const { userToken } = req.body;
  // console.log(userToken);

  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.GOOGLE_CLIENT_ID
  });

  const payload = ticket.getPayload();
  // console.log(payload);
  const { name, email, picture, sub } = payload;
  const password = Date.now() + sub;

  // check if user exist
  const user = await User.findOne({ email });

  // Get UserAgent
  const ua = parser(req.headers['user-agent']);
  const userAgent = [ua.ua];

  if (!user) {
    // register new user
    const newUser = await User.create({
      name,
      email,
      password,
      photo: picture,
      isVerified: true,
      userAgent
    });

    if (newUser) {
      // Generate Token
      const token = generateToken(newUser._id);

      // Send HTTP-only cookie
      res.cookie('token', token, {
        path: '/',
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: 'none',
        secure: true
      });

      const {
        _id,
        name,
        email,
        phone,
        bio,
        photo,
        permitUploaded,
        role,
        isVerified
      } = newUser;

      res.status(201).json({
        _id,
        name,
        email,
        phone,
        bio,
        photo,
        permitUploaded,
        role,
        isVerified,
        token
      });
    }
  }

  // User exists, login
  if (user) {
    // Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie('token', token, {
      path: '/',
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: 'none',
      secure: true
    });

    const {
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      permitUploaded,
      role,
      isVerified
    } = user;

    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      permitUploaded,
      role,
      isVerified,
      token
    });
  }
});

const photoUpload = async (req, res, next) => {
  try {
    if (!req.files || !!req.files.images === false) {
      return res.status(400).send('No files were uploaded.');
    }

    const validateResult = imageValidate(req.files.images);
    if (validateResult.error) {
      return res.status(400).send(validateResult.error);
    }

    const path = require('path');
    const { v4: uuidv4 } = require('uuid');
    const uploadDirectory = path.resolve(
      __dirname,
      '../../frontend',
      'public',
      'images',
      'photos'
    );

    //console.log(req.query.userId);
    let user = await User.findById(req.query.userId).orFail();

    let imagesTable = [];
    // if (Array.isArray(req.files.images)) {
    //   res.send('You sent' + req.files.images.length + ' images');
    // } else {
    //   res.send('You sent only one image.');
    // }

    if (Array.isArray(req.files.images)) {
      imagesTable = req.files.images;
    } else {
      imagesTable.push(req.files.images);
    }

    for (let image of imagesTable) {
      // console.log(path.extname(image.name));
      // console.log(uuidv4());
      var fileName = uuidv4() + path.extname(image.name);
      var uploadPath = uploadDirectory + '/' + fileName;
      user.photo = '/images/photos/' + fileName;
      image.mv(uploadPath, function (err) {
        if (err) {
          return res.status(500).send(err);
        }
      });
    }
    await user.save();
    return res.send({ message: 'Files uploaded!' });
  } catch (err) {
    next(err);
  }
};

// Get Applicants
const getApplicants = asyncHandler(async (req, res) => {
  const applicants = await User.find({ role: 'applicant' })
    .sort('-createdAt')
    .select('-password');
  if (!applicants) {
    res.status(500);
    throw new Error('Something went wrong');
  }
  res.status(200).json(applicants);
});

// Upload Exam Permit
const sendPdftoEmail = async (req, res, next) => {
  const { userId, to, subject, text, username } = req.body;
  //const user = await User.findById(userId);
  const pdfBuffer = req.files.pdfFile; // The PDF content as a buffer
  //console.log(pdfBuffer);
  const path = require('path');
  const { v4: uuidv4 } = require('uuid');
  const uploadDirectory = path.resolve(__dirname, '../files');
  let user = await User.findById(userId).orFail();

  try {
    if (!req.files.pdfFile) {
      return res.status(400).send('No files were uploaded.');
    }

    let imagesTable = [];

    if (Array.isArray(req.files.pdfFile)) {
      imagesTable = req.files.pdfFile;
    } else {
      imagesTable.push(req.files.pdfFile);
    }

    for (let image of imagesTable) {
      var fileName = uuidv4() + path.extname(image.name);
      var uploadPath = uploadDirectory + '/' + fileName;
      //user.permit = '/images/exampermits/' + fileName;
      user.emailPdf = 'files/' + fileName;
      user.emailPdfUploaded = true;
      image.mv(uploadPath, function (err) {
        if (err) {
          return res.status(500).send(err);
        }
      });
    }
    await user.save();

    // Send Email
    //const subject = 'Verify Your Account - AUTH:AFPSAT';
    const send_to = to;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = 'noreply@afpres.com';
    const template = 'pdfAttachment';
    const name = username;
    const link = text;
    const filename = 'afpsat_result.pdf';
    //const pdffile = pdfBuffer;
    const pdffile = user.emailPdf;
    await sendPdfEmail(
      subject,
      send_to,
      filename,
      pdffile,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    return res
      .status(200)
      .json({ message: `Files uploaded and sent to ${email}!` });
  } catch (err) {
    next(err);
  }
};

// Upload Exam Permit
const permitUpload = async (req, res, next) => {
  try {
    if (!req.files || !!req.files.images === false) {
      return res.status(400).send('No files were uploaded.');
    }

    const validateResult = permitValidate(req.files.images);
    if (validateResult.error) {
      return res.status(400).send(validateResult.error);
    }

    const path = require('path');
    const { v4: uuidv4 } = require('uuid');
    // const uploadDirectory = path.resolve(
    //   __dirname,
    //   '../../frontend',
    //   'public',
    //   'images',
    //   'exampermits'
    // );
    const uploadDirectory = path.resolve(__dirname, '../files');

    //console.log(req.query.userId);
    let user = await User.findById(req.query.userId).orFail();

    let imagesTable = [];
    // if (Array.isArray(req.files.images)) {
    //   res.send('You sent' + req.files.images.length + ' images');
    // } else {
    //   res.send('You sent only one image.');
    // }

    if (Array.isArray(req.files.images)) {
      imagesTable = req.files.images;
    } else {
      imagesTable.push(req.files.images);
    }

    for (let image of imagesTable) {
      // console.log(path.extname(image.name));
      // console.log(uuidv4());
      var fileName = uuidv4() + path.extname(image.name);
      var uploadPath = uploadDirectory + '/' + fileName;
      //user.permit = '/images/exampermits/' + fileName;
      user.permit = 'files/' + fileName;
      user.permitUploaded = true;
      image.mv(uploadPath, function (err) {
        if (err) {
          return res.status(500).send(err);
        }
      });
    }
    await user.save();
    return res.send({ message: 'Files uploaded!' });
  } catch (err) {
    next(err);
  }
};

const getPdfUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const {
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      address,
      permit,
      permitUploaded
    } = user;

    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      address,
      permit,
      permitUploaded
    });
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// Approve Exam Permit
const approveExamPermit = asyncHandler(async (req, res) => {
  const { proctorId, id, signatoryId } = req.body;
  const user = await User.findById(id);

  if (user) {
    const { pyschometId, permitApproved } = user;

    if (permitApproved === false) {
      user.permitApproved = true;
      user.pyschometId = proctorId;
      user.signatoryId = signatoryId;
      await user.save();
      res.send('Exam Permit Approved!');
    } else {
      user.permitApproved = false;
      user.pyschometId = '';
      user.signatoryId = '';
      await user.save();
      res.send('Exam Permit Disapproved!');
    }
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// Approve Abstract Permit
const approveAbstractExam = asyncHandler(async (req, res) => {
  const { proctorId, id, batchCode, signatoryId } = req.body;
  const user = await User.findById(id);

  if (user) {
    const { pyschometId, approveAbstract } = user;

    if (approveAbstract === false) {
      user.approveAbstract = true;
      user.pyschometId = proctorId;
      user.batchCode = batchCode;
      user.signatoryId = signatoryId;
      await user.save();
      res.send('Abstract Reasoning Started!');
    } else {
      user.approveAbstract = false;
      user.examResults = user.examResults - 1;
      user.pyschometId = '';
      user.batchCode = '';
      user.signatoryId = '';
      await user.save();
      res.send('Abstract Reasoning Stopped!');
    }
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// Approved Verbal Exam
const approveVerbalExam = asyncHandler(async (req, res) => {
  const { proctorId, id, batchCode, signatoryId } = req.body;
  const user = await User.findById(id);

  if (user) {
    const { pyschometId, approvedVerbal } = user;

    if (approvedVerbal === false) {
      user.approvedVerbal = true;
      user.pyschometId = proctorId;
      user.batchCode = batchCode;
      user.signatoryId = signatoryId;
      await user.save();
      res.send('Verbal Reasoning Started!');
    } else {
      user.approvedVerbal = false;
      user.pyschometId = '';
      user.examResults = user.examResults - 1;
      user.batchCode = '';
      user.signatoryId = '';
      await user.save();
      res.send('Verbal Reasoning Stopped!');
    }
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// Approve Numerical Exam
const approveNumericalExam = asyncHandler(async (req, res) => {
  const { proctorId, id, batchCode, signatoryId } = req.body;
  const user = await User.findById(id);

  if (user) {
    const { pyschometId, approvedNumerical } = user;

    if (approvedNumerical === false) {
      user.approvedNumerical = true;
      user.pyschometId = proctorId;
      user.batchCode = batchCode;
      user.signatoryId = signatoryId;
      await user.save();
      res.send('Numerical Reasoning Started!');
    } else {
      user.approvedNumerical = false;
      user.pyschometId = '';
      user.examResults = user.examResults - 1;
      user.batchCode = '';
      user.signatoryId = '';
      await user.save();
      res.send('Numerical Reasoning Stopped!');
    }
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// Change Form Set
const changeFormSet = asyncHandler(async (req, res) => {
  const { proctorId, id, formSet, signatoryId } = req.body;
  const user = await User.findById(id);

  if (user) {
    if (formSet === 'a') {
      user.formSet = 'b';
      user.pyschometId = proctorId;
      user.signatoryId = signatoryId;
      await user.save();
      res.send('Exam change to Form B');
    } else {
      if (formSet === 'b') {
        user.formSet = 'c';
        user.pyschometId = proctorId;
        user.signatoryId = signatoryId;
        await user.save();
        res.send('Exam change to Form C');
      } else {
        if (formSet === 'c') {
          user.formSet = 'd';
          user.pyschometId = proctorId;
          user.signatoryId = signatoryId;
          await user.save();
          res.send('Exam change to Form C');
        } else {
          user.formSet = 'a';
          user.pyschometId = proctorId;
          user.signatoryId = signatoryId;
          await user.save();
          res.send('Exam change to Form A');
        }
      }
    }
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// saveUserScore
const saveUserScore = asyncHandler(async (req, res) => {
  const { id, totalQuestionsAnswered, totalCorrectAnswer, numberPercentage } =
    req.body;
  const user = await User.findById(id);

  if (user) {
    let examSection = user.examResults + 1;

    user.numberItems = totalQuestionsAnswered;
    user.numberScore = totalCorrectAnswer;
    user.numberPercent = numberPercentage;
    user.approvedNumerical = false;

    let totalScore = totalCorrectAnswer + user.verbalScore + user.abstractScore;
    const totalItems =
      totalQuestionsAnswered + user.verbalItems + user.abstractItems;

    const percentage = (totalScore / totalItems) * 100;
    const roundedPercentage = (Math.round(percentage * 100) / 100).toFixed(2); // 12.35

    if (examSection === 3) {
      user.examResults = 0;
      user.hasTaken = true;
      user.totalScore = totalScore;
      user.totalPercent = roundedPercentage;
    } else {
      user.examResults = examSection;
      user.hasTaken = false;
    }

    let d = new Date();

    totalScore <= 33
      ? ((user.grade = 'F'),
        (user.description = 'Very Poor'),
        (user.remarks = 'Below Passing Score'),
        (user.eligibility = 'Retake after three (3) months'))
      : totalScore >= 34 && totalScore <= 48
      ? ((user.grade = 'E'),
        (user.description = 'Poor'),
        (user.remarks = 'Below Passing Score'),
        (user.eligibility = 'Retake after three (3) months'))
      : totalScore >= 49 && totalScore <= 63
      ? ((user.grade = 'D'),
        (user.description = 'Average'),
        (user.remarks = 'Passing Score'),
        (user.eligibility = '(Enlistment Only)'))
      : totalScore >= 64 && totalScore <= 79
      ? ((user.grade = 'C'),
        (user.description = 'High Average'),
        (user.remarks = 'Passed'),
        (user.eligibility = '(Enlistment Only)'))
      : totalScore >= 80 && totalScore <= 94
      ? ((user.grade = 'B'),
        (user.description = 'Above Average'),
        (user.remarks = 'Passed'),
        (user.eligibility = '(Enlistment and Commission)'))
      : totalScore >= 95 && totalScore <= 150
      ? ((user.grade = 'A'),
        (user.description = 'Outstanding'),
        (user.remarks = 'Passed'),
        (user.eligibility = '(Enlistment and Commission)'))
      : ((user.grade = ''),
        (user.description = ''),
        (user.remarks = ''),
        (user.eligibility = ''));

    user.exam_date = d.toLocaleDateString();
    user.next_retake = d.setMonth(d.getMonth() + 3);

    await user.save();

    // save score to resultsTable
    if (examSection === 3) {
      let td = new Date();
      //save score
      const result = await Result.create({
        user: user._id,
        last_name: user.name,
        purposeOfExam: user.purposeOfExam,
        branchOfService: user.branchOfService,
        abstract_score: user.abstractScore,
        abstract_percent: user.abstractPercent,
        numeric_score: totalCorrectAnswer,
        numberPercent: numberPercentage,
        verbal_score: user.verbalScore,
        verbal_percent: user.verbalPercent,
        total_score: totalScore,
        totalPercent: roundedPercentage,
        grade: user.grade,
        description: user.description,
        remarks: user.remarks,
        eligibility: user.eligibility,
        exam_date: td.toLocaleDateString(),
        next_retake: td.setMonth(td.getMonth() + 3),
        batchCode: user.batchCode
      });
    }
    res.send('User valid!');
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// saveAbstractScore
const saveAbstractScore = asyncHandler(async (req, res) => {
  const { id, totalQuestionsAnswered, totalCorrectAnswer, abstractPercentage } =
    req.body;
  const user = await User.findById(id);

  if (user) {
    let examSection = user.examResults + 1;

    user.abstractItems = totalQuestionsAnswered;
    user.abstractScore = totalCorrectAnswer;
    user.abstractPercent = abstractPercentage;
    user.approveAbstract = false;

    let totalScore = totalCorrectAnswer + user.verbalScore + user.numberScore;
    const totalItems =
      totalQuestionsAnswered + user.verbalItems + user.numberItems;
    const percentage = (totalScore / totalItems) * 100;
    const roundedPercentage = (Math.round(percentage * 100) / 100).toFixed(2); // 12.35

    if (examSection === 3) {
      user.examResults = 0;
      user.hasTaken = true;
      user.totalScore = totalScore;
      user.totalPercent = roundedPercentage;
    } else {
      user.examResults = examSection;
      user.hasTaken = false;
    }

    let d = new Date();

    totalScore <= 33
      ? ((user.grade = 'F'),
        (user.description = 'Very Poor'),
        (user.remarks = 'Below Passing Score'),
        (user.eligibility = 'Retake after three (3) months'))
      : totalScore >= 34 && totalScore <= 48
      ? ((user.grade = 'E'),
        (user.description = 'Poor'),
        (user.remarks = 'Below Passing Score'),
        (user.eligibility = 'Retake after three (3) months'))
      : totalScore >= 49 && totalScore <= 63
      ? ((user.grade = 'D'),
        (user.description = 'Average'),
        (user.remarks = 'Passing Score'),
        (user.eligibility = '(Enlistment Only)'))
      : totalScore >= 64 && totalScore <= 79
      ? ((user.grade = 'C'),
        (user.description = 'High Average'),
        (user.remarks = 'Passed'),
        (user.eligibility = '(Enlistment Only)'))
      : totalScore >= 80 && totalScore <= 94
      ? ((user.grade = 'B'),
        (user.description = 'Above Average'),
        (user.remarks = 'Passed'),
        (user.eligibility = '(Enlistment and Commission)'))
      : totalScore >= 95 && totalScore <= 150
      ? ((user.grade = 'A'),
        (user.description = 'Outstanding'),
        (user.remarks = 'Passed'),
        (user.eligibility = '(Enlistment and Commission)'))
      : ((user.grade = ''),
        (user.description = ''),
        (user.remarks = ''),
        (user.eligibility = ''));

    user.exam_date = d.toLocaleDateString();
    user.next_retake = d.setMonth(d.getMonth() + 3);

    await user.save();

    // save score to resultsTable
    if (examSection === 3) {
      let td = new Date();
      //save score
      const result = await Result.create({
        user: user._id,
        last_name: user.name,
        purposeOfExam: user.purposeOfExam,
        branchOfService: user.branchOfService,
        abstract_score: totalCorrectAnswer,
        abstract_percent: abstractPercentage,
        verbal_score: user.verbalScore,
        verbal_percent: user.verbalPercent,
        numeric_score: user.numberScore,
        numberPercent: user.numberPercent,
        total_score: totalScore,
        totalPercent: roundedPercentage,
        grade: user.grade,
        description: user.description,
        remarks: user.remarks,
        eligibility: user.eligibility,
        exam_date: td.toLocaleDateString(),
        next_retake: td.setMonth(td.getMonth() + 3),
        batchCode: user.batchCode
      });
    }
    res.send('User valid!');
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

//saveVerbalScore
const saveVerbalScore = asyncHandler(async (req, res) => {
  const { id, totalQuestionsAnswered, totalCorrectAnswer, verbalPercentage } =
    req.body;
  const user = await User.findById(id);

  if (user) {
    user.verbalItems = totalQuestionsAnswered;
    user.verbalScore = totalCorrectAnswer;
    user.verbalPercent = verbalPercentage;

    let totalScore = totalCorrectAnswer + user.abstractScore + user.numberScore;
    const totalItems =
      totalQuestionsAnswered + user.abstractItems + user.numberItems;
    const percentage = (totalScore / totalItems) * 100;
    const roundedPercentage = (Math.round(percentage * 100) / 100).toFixed(2); // 12.35

    let examSection = user.examResults + 1;
    if (examSection === 3) {
      user.examResults = 0;
      user.hasTaken = true;
      user.totalScore = totalScore;
      user.totalPercent = roundedPercentage;
    } else {
      user.examResults = examSection;
      user.hasTaken = false;
    }

    user.approvedVerbal = false;

    let d = new Date();

    totalScore <= 33
      ? ((user.grade = 'F'),
        (user.description = 'Very Poor'),
        (user.remarks = 'Below Passing Score'),
        (user.eligibility = 'Retake after three (3) months'))
      : totalScore >= 34 && totalScore <= 48
      ? ((user.grade = 'E'),
        (user.description = 'Poor'),
        (user.remarks = 'Below Passing Score'),
        (user.eligibility = 'Retake after three (3) months'))
      : totalScore >= 49 && totalScore <= 63
      ? ((user.grade = 'D'),
        (user.description = 'Average'),
        (user.remarks = 'Passing Score'),
        (user.eligibility = '(Enlistment Only)'))
      : totalScore >= 64 && totalScore <= 79
      ? ((user.grade = 'C'),
        (user.description = 'High Average'),
        (user.remarks = 'Passed'),
        (user.eligibility = '(Enlistment Only)'))
      : totalScore >= 80 && totalScore <= 94
      ? ((user.grade = 'B'),
        (user.description = 'Above Average'),
        (user.remarks = 'Passed'),
        (user.eligibility = '(Enlistment and Commission)'))
      : totalScore >= 95 && totalScore <= 150
      ? ((user.grade = 'A'),
        (user.description = 'Outstanding'),
        (user.remarks = 'Passed'),
        (user.eligibility = '(Enlistment and Commission)'))
      : ((user.grade = ''),
        (user.description = ''),
        (user.remarks = ''),
        (user.eligibility = ''));

    user.exam_date = d.toLocaleDateString();
    user.next_retake = d.setMonth(d.getMonth() + 3);

    await user.save();

    // save score to resultsTable
    if (examSection === 3) {
      let td = new Date();
      //save score
      const result = await Result.create({
        user: user._id,
        last_name: user.name,
        purposeOfExam: user.purposeOfExam,
        branchOfService: user.branchOfService,
        verbal_score: totalCorrectAnswer,
        verbal_percent: verbalPercentage,
        abstract_score: user.abstractScore,
        abstract_percent: user.abstractPercent,
        numeric_score: user.numberScore,
        numberPercent: user.numberPercent,
        total_score: totalScore,
        totalPercent: roundedPercentage,
        grade: user.grade,
        description: user.description,
        remarks: user.remarks,
        eligibility: user.eligibility,
        exam_date: td.toLocaleDateString(),
        next_retake: td.setMonth(td.getMonth() + 3),
        batchCode: user.batchCode
      });
    }

    res.send('User valid!');
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// Get Applicant
const getApplicant = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);

  if (user) {
    const {
      _id,
      name,
      email,
      birthDate,
      phone,
      street,
      city,
      country,
      bio,
      photo,
      role,
      isVerified,
      address,
      permit,
      permitUploaded,
      permitApproved,
      approveAbstract,
      approvedVerbal,
      approvedNumerical,
      hasTaken,
      abstractScore,
      abstractItems,
      abstractPercent,
      formSet,
      verbalItems,
      verbalScore,
      verbalPercent,
      numberItems,
      numberScore,
      numberPercent,
      totalScore,
      totalPercent,
      description,
      eligibility,
      grade,
      remarks,
      exam_date,
      next_retake,
      branchOfService,
      purposeOfExam,
      batchCode,
      signatoryId
    } = user;

    res.status(200).json({
      _id,
      name,
      email,
      birthDate,
      phone,
      street,
      city,
      country,
      bio,
      photo,
      role,
      isVerified,
      address,
      permit,
      permitUploaded,
      permitApproved,
      approveAbstract,
      approvedVerbal,
      approvedNumerical,
      hasTaken,
      abstractScore,
      abstractItems,
      abstractPercent,
      formSet,
      verbalItems,
      verbalScore,
      verbalPercent,
      numberItems,
      numberScore,
      numberPercent,
      totalScore,
      totalPercent,
      description,
      eligibility,
      grade,
      remarks,
      exam_date,
      next_retake,
      branchOfService,
      purposeOfExam,
      batchCode,
      signatoryId
    });
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// Update Applicant
const updateApplicant = asyncHandler(async (req, res) => {
  const { id } = req.body;
  const user = await User.findById(id);

  if (user) {
    const {
      name,
      email,
      birthDate,
      phone,
      photo,
      role,
      isVerified,
      street,
      city,
      country,
      branchOfService,
      purposeOfExam
    } = user;

    user.email = email;
    user.name = req.body.name || name;
    user.birthDate = req.body.birthDate || birthDate;
    user.phone = req.body.phone || phone;
    //user.address = req.body.address || address;
    user.photo = req.body.photo || photo;
    user.street = req.body.street || street;
    user.city = req.body.city || city;
    user.country = req.body.country || country;
    user.branchOfService = req.body.branchOfService || branchOfService;
    user.purposeOfExam = req.body.purposeOfExam || purposeOfExam;
    user.hasPurpose = true;
    const updatedUser = await user.save();

    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      birthDate: updatedUser.birthDate,
      phone: updatedUser.phone,
      street: updatedUser.street,
      city: updatedUser.city,
      country: updatedUser.country,
      photo: updatedUser.photo,
      role: updatedUser.role,
      isVerified: updatedUser.isVerified,
      branchOfService: updatedUser.branchOfService,
      purposeOfExam: updatedUser.purposeOfExam,
      hasPurpose: updatedUser.hasPurpose
    });
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// profileUpload
const profileUpload = async (req, res, next) => {
  const { userId } = req.params;

    try {
    if (!req.files || !!req.files.images === false) {
      return res.status(400).send('No files were uploaded.');
    }

    const validateResult = imageValidate(req.files.images);
    if (validateResult.error) {
      return res.status(400).send(validateResult.error);
    }

    const path = require('path');
    const { v4: uuidv4 } = require('uuid');
    const uploadDirectory = path.resolve(
      __dirname,
      '../../frontend',
      'public',
      'images',
      'photos'
    );

    //console.log(req.query.userId);
    let user = await User.findById(userId).orFail();

    let imagesTable = [];

    if (Array.isArray(req.files.images)) {
      imagesTable = req.files.images;
    } else {
      imagesTable.push(req.files.images);
    }

    for (let image of imagesTable) {
      var fileName = uuidv4() + path.extname(image.name);
      var uploadPath = uploadDirectory + '/' + fileName;
      user.photo = '/images/photos/' + fileName;
      image.mv(uploadPath, function (err) {
        if (err) {
          return res.status(500).send(err);
        }
      });
    }
    await user.save();
    return res.send({ message: 'Files uploaded!' });
  } catch (err) {
    next(err);
  }
 };

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
  getUsers,
  loginStatus,
  upgradeUser,
  sendAutomatedEmail,
  sendVerificationEmail,
  verifyUser,
  forgotPassword,
  resetPassword,
  changePassword,
  changeAddress,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle,
  photoUpload,
  getApplicants,
  sendPdftoEmail,
  permitUpload,
  getPdfUser,
  approveExamPermit,
  approveAbstractExam,
  approveVerbalExam,
  approveNumericalExam,
  changeFormSet,
  saveUserScore,
  saveAbstractScore,
  saveVerbalScore,
  getApplicant,
  updateApplicant,
  sendOtpCode,
  loginWithOtp,
  profileUpload,
};
