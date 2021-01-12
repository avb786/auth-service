const accountService = require('../services/user-authenticate');
const { responseGenerator } = require('../constants/response-generator')
const authenticate = (req, res, next) => {
    const { email, password } = req.body;
    const ipAddress = req.ip;
    accountService.authenticate({ email, password, ipAddress })
        .then(({ refreshToken, ...account }) => {
            setTokenCookie(res, refreshToken);
            res.json(account);
        })
        .catch(next);
}

function setTokenCookie(res, token) {
    // create cookie with refresh token that expires in 7 days
    const cookieOptions = {
        httpOnly: true,
        expires: new Date(Date.now() + 7*24*60*60*1000)
    };
    res.cookie('refreshToken', token, cookieOptions);
}

const refreshToken = (req, res, next) => {
    const token = req.cookies.refreshToken;
    const ipAddress = req.ip;
    accountService.refreshToken({ token, ipAddress })
        .then(({ refreshToken, ...account }) => {
            setTokenCookie(res, refreshToken);
            res.json(account);
        })
        .catch(next);
}

const revokeToken = (req, res, next) =>{
    // accept token from request body or cookie
    const token = req.body.token || req.cookies.refreshToken;
    const ipAddress = req.ip;
    
    if (!token) return responseGenerator(res, {}, 400, 'Token is required', false);

    // users can revoke their own tokens and admins can revoke any tokens
    if (!req.user.ownsToken(token) && req.user.role !== Role.Admin) {
        return responseGenerator(res, {}, 401, 'Unauthorized', false)
    }
    
    accountService.revokeToken({ token, ipAddress })
        .then(() => responseGenerator(res, {}, 200, 'Token revoked', false))
        .catch(next);
}

const register = (req, res, next) => {
    accountService.register(req.body, req.get('origin'))
        .then(() => responseGenerator(res, {}, 200, 'Registration successful, please check your email for verification instructions', false))
        .catch();
}

const verifyEmail = (req, res, next) =>{
    accountService.verifyEmail(req.body)
        .then(() => responseGenerator(res, {}, 200, 'Verification successful, you can now login', false))
        .catch(next);
}

const forgotPassword = (req, res, next) => {
    accountService.forgotPassword(req.body, req.get('origin'))
        .then(() => responseGenerator(res, {}, 200, 'Please check your email for password reset instructions', false))
        .catch(next);
}
const validateResetToken = (req, res, next) => {
    accountService.validateResetToken(req.body)
        .then(() => responseGenerator(res, {}, 200, 'Token is Valid', false))
        .catch(next);
}
const resetPassword = (req, res, next) => {
    accountService.resetPassword(req.body)
        .then(() => responseGenerator(res, {}, 200, 'Password reset successful, you can now login', false))
        .catch(next);
}

const getAll = (req, res, next) =>{
    accountService.getAll()
        .then(accounts => responseGenerator(res, accounts, 200, 'Accounts Fetch Successfully', false))
        .catch(next);
}
const  getById = (req, res, next) => {
    // users can get their own account and admins can get any account
    if (req.params.id !== req.user.id && req.user.role !== Role.Admin) {
        return responseGenerator(res, {}, 401, 'Unauthorized', true);
    }
    accountService.getById(req.params.id)
        .then(account => account ? responseGenerator(res, account, 200, 'Found data', false) : responseGenerator(res, {}, 404, 'Found No data', true))
        .catch(next);
}

const create = (req, res, next) => {
    accountService.create(req.body)
        .then(account => res.json(account))
        .catch(next);
}

const update = (req, res, next) => {
    // users can update their own account and admins can update any account
    if (req.params.id !== req.user.id && req.user.role !== Role.Admin) {
        return responseGenerator(res, {}, 401, 'Unauthorized', true);
    }

    accountService.update(req.params.id, req.body)
        .then(account => res.json(account))
        .catch(next);
}
const _delete = (req, res, next) => {
    // users can delete their own account and admins can delete any account
    if (req.params.id !== req.user.id && req.user.role !== Role.Admin) {
        return responseGenerator(res, {}, 401, 'Unauthorized', true);
    }

    accountService._delete(req.params.id)
        .then(() => responseGenerator(res, {}, 200, 'Account deleted Successfully', true))
        .catch(next);
}
module.exports = {
    authenticate,
    refreshToken,
    revokeToken,
    register,
    verifyEmail,
    forgotPassword,
    validateResetToken,
    resetPassword,
    getAll,
    getById,
    create,
    update,
    _delete
}