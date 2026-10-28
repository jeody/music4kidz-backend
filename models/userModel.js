const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please add a name']
    },
    email: {
      type: String,
      required: [true, 'Please add an email'],
      unique: true,
      trim: true,
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        'Please enter a valid email'
      ]
    },
    password: {
      type: String,
      required: [true, 'Please add a password']
    },
    role: {
      type: String,
      required: [true],
      default: 'student',
      enum: [
        'student',
        'coach',
        'psychometrician',
        'psychologist',
        'admin',
        'suspended'
      ]
    },
    photo: {
      type: String,
      required: [true, 'Please add a photo'],
      default: '/images/profile.jpg'
    },
    birthdate: {
      type: Date
    },
    phone: {
      type: String,
      default: '+63'
    },
    street: {
      type: String
    },
    barangay: {
      type: String
    },
    city: {
      type: String
    },
    cityId: {
      type: String
    },
    province: {
      type: String
    },
    provinceId: {
      type: String
    },
    region: {
      type: String
    },
    regionId: {
      type: String
    },
    country: {
      type: String,
      default: 'Philippines'
    },
    address: {
      type: String,
    },
    wishlist: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product'
    },
    balance: {
      type: Number,
      default: 0
    },
    cartItems: {
      type: [Object]
    },
    isVerified: {
      type: Boolean,
      default: false
    },
    stripeCustomerId: {
      type: String
      // required: true,
    },
    bio: {
      type: String,
      default: 'bio'
    },
    userAgent: {
      type: Array,
      required: true,
      default: []
    },
    hasPurpose: {
      type: Boolean,
      default: false
    },
    permit: {
      type: String,
      default: ''
    },
    permitUploaded: {
      type: Boolean,
      default: false
    },
    emailPdf: {
      type: String,
      default: ''
    },
    emailPdfUploaded: {
      type: Boolean,
      default: false
    },
    permitApproved: {
      type: Boolean,
      default: false
    },
    approveAbstract: {
      type: Boolean,
      default: false
    },
    approvedVerbal: {
      type: Boolean,
      default: false
    },
    approvedNumerical: {
      type: Boolean,
      default: false
    },
    pyschometId: {
      type: String
    },
    formSet: {
      type: String,
      default: 'a'
    },
    examResults: {
      type: Number,
      default: 0
    },
    abstractItems: {
      type: Number,
      default: 0
    },
    abstractScore: {
      type: Number,
      default: 0
    },
    abstractPercent: {
      type: Number,
      default: 0
    },
    numberItems: {
      type: Number,
      default: 0
    },
    numberScore: {
      type: Number,
      default: 0
    },
    numberPercent: {
      type: Number,
      default: 0
    },
    verbalItems: {
      type: Number,
      default: 0
    },
    verbalScore: {
      type: Number,
      default: 0
    },
    verbalPercent: {
      type: Number,
      default: 0
    },
    grade: {
      type: String,
      trim: true
    },
    description: {
      type: String,
      trim: true
    },
    remarks: {
      type: String,
      trim: true
    },
    eligibility: {
      type: String,
      trim: true
    },
    exam_date: {
      type: Date
    },
    next_retake: {
      type: Date
    },
    hasTaken: {
      type: Boolean,
      default: false
    },
    totalScore: {
      type: Number,
      default: 0
    },
    totalPercent: {
      type: Number,
      default: 0
    },
    branchOfService: {
      type: String,
      trim: true
    },
    purposeOfExam: {
      type: String,
      trim: true
    },
    batchCode: {
      type: String
    },
    signatoryId: {
      type: String
    },
    isAddedMember: {
      type: Boolean,
      default: false
    },
    memberId: {
      type: String
    }
  },
  {
    timestamps: true,
    minimize: false
  }
);

// Encrypt password before saving to DB
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(this.password, salt);
  this.password = hashedPassword;
  next();
});

const User = mongoose.model('User', userSchema);
module.exports = User;
