const express = require('express');
const router = express.Router();
const roleName = require('../constants/role')

const { authenticateSchema, revokeTokenSchema, registerSchema, verifyEmailSchema, forgotPasswordSchema, validateResetTokenSchema, resetPasswordSchema, createSchema, updateSchema } = require('../middleware/authenticate');
const { authorize } = require('../middleware/authorize');
const { authenticate, refreshToken, revokeToken, register, verifyEmail, forgotPassword, validateResetToken, resetPassword, getAll, create, update, getById, _delete } = require('../controller/user-account')


router.post('/authenticate', authenticateSchema, authenticate);
router.post('/refresh-token', refreshToken);
router.post('/revoke-token', authorize(), revokeTokenSchema, revokeToken);
router.post('/register', registerSchema, register);
router.post('/verify-email', verifyEmailSchema, verifyEmail);
router.post('/forgot-password', forgotPasswordSchema, forgotPassword);
router.post('/validate-reset-token', validateResetTokenSchema, validateResetToken);
router.post('/reset-password', resetPasswordSchema, resetPassword);
router.get('/', authorize(roleName.Admin), getAll);
router.get('/:id', authorize(), getById);
router.post('/create', authorize(roleName.Admin), createSchema, create);
router.put('/:id', authorize(), updateSchema, update);
router.delete('/:id', authorize(), _delete);

module.exports = router;
