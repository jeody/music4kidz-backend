const express = require('express');
const router = express.Router();
const {
  protect,
  adminOnly,
  authorOnly,
  psychometricianOnly
} = require('../middleware/authMiddleware');
const {
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
  permitUpload,
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
  sendPdftoEmail,
  loginWithOtp,
  sendOtpCode,
  profileUpload
} = require('../controllers/userController');

router.post('/register', registerUser);
router.post('/login', loginUser);
router.get('/logout', logoutUser);
router.get('/getUser', protect, getUser);
router.patch('/updateUser', protect, updateUser);
router.post('/upload', protect, photoUpload);
router.post('/profileUpload/:userId', protect, profileUpload);
router.post('/permitUpload', protect, permitUpload);
router.post('/sendPdftoEmail', protect, sendPdftoEmail);
router.post(
  '/approveExamPermit',
  protect,
  psychometricianOnly,
  approveExamPermit
);
router.post(
  '/approveAbstractExam',
  protect,
  psychometricianOnly,
  approveAbstractExam
);
router.post(
  '/approveVerbalExam',
  protect,
  psychometricianOnly,
  approveVerbalExam
);
router.post(
  '/approveNumericalExam',
  protect,
  psychometricianOnly,
  approveNumericalExam
);

router.delete('/:id', protect, adminOnly, deleteUser);
router.get('/getUsers', protect, adminOnly, getUsers);
router.get('/getApplicants', protect, psychometricianOnly, getApplicants);
router.get('/getApplicant/:id', protect, psychometricianOnly, getApplicant);
router.patch('/updateApplicant', protect, psychometricianOnly, updateApplicant);
router.post('/changeFormSet', protect, psychometricianOnly, changeFormSet);
router.get('/loginStatus', loginStatus);
router.post('/upgradeUser', protect, adminOnly, upgradeUser);
router.post('/sendAutomatedEmail', protect, sendAutomatedEmail);

router.post('/sendVerificationEmail', protect, sendVerificationEmail);
router.patch('/verifyUser/:verificationToken', verifyUser);
router.post('/forgotPassword', forgotPassword);
router.patch('/resetPassword/:resetToken', resetPassword);
router.patch('/changePassword', protect, changePassword);
router.patch('/changeAddress', protect, changeAddress);
router.patch('/saveUserScore', protect, saveUserScore);
router.patch('/saveAbstractScore', protect, saveAbstractScore);
router.patch('/saveVerbalScore', protect, saveVerbalScore);

router.post('/sendLoginCode/:email', sendLoginCode);
router.post('/loginWithCode/:email', loginWithCode);
router.post('/sendOtpCode/:email', sendOtpCode);
router.post('/loginWithOtp/:email', loginWithOtp);
router.post('/google/callback', loginWithGoogle);

module.exports = router;
