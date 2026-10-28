const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');
const jwt = require('jsonwebtoken');

// Logged in User only
const protect = asyncHandler(async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      res.status(401);
      throw new Error('Not authorized, please login!');
    }

    // Verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    // Get user ID from token
    const user = await User.findById(verified.id).select('-password');

    if (!user) {
      res.status(404);
      throw new Error('User not found!');
    }

    if (user.role === 'suspended') {
      res.status(404);
      throw new Error('User suspended, please contact support!');
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401);
    throw new Error('Not authorized, please login!');
  }
});

// Admin Only
const adminOnly = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(401);
    throw new Error('Not authorized as an admin!');
  }
});

// Author Only
const authorOnly = asyncHandler(async (req, res, next) => {
  if (req.user.role === 'author' || req.user.role === 'admin') {
    next();
  } else {
    res.status(401);
    throw new Error('Not authorized as author!');
  }
});

// Verified Only
const verifiedOnly = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.isVerified) {
    next();
  } else {
    res.status(401);
    throw new Error('Not authorized, account not verified!');
  }
});

// ============ 1. user middleware in middleware folder ================ //
const userOnly = asyncHandler(async (req, res, next) => {
  if (req.user.id === req.params.id || req.user.role === 'admin') {
    next();
  } else {
    res.status(401);
    throw new Error('Not authorized!');
  }
});

// Psychometrician Only
const psychometricianOnly = asyncHandler(async (req, res, next) => {
  if (req.user.role === 'psychometrician' || req.user.role === 'admin') {
    next();
  } else {
    res.status(401);
    throw new Error('Not authorized as psychometrician!');
  }
});

// Coach Only
const coachOnly = asyncHandler(async (req, res, next) => {
  if (req.user.role === 'coach' || req.user.role === 'admin') {
    next();
  } else {
    res.status(401);
    throw new Error('Not authorized as coach!');
  }
});

// Psychologist Only
const psychologistOnly = asyncHandler(async (req, res, next) => {
  if (req.user.role === 'psychologist') {
    next();
  } else {
    res.status(401);
    throw new Error('Not authorized as psychologist!');
  }
});

module.exports = {
  protect,
  adminOnly,
  authorOnly,
  psychometricianOnly,
  coachOnly,
  psychologistOnly,
  verifiedOnly,
  userOnly,
};
