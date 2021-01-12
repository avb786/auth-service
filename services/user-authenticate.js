const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const crypto = require("crypto");
const { sendAlreadyRegisteredEmail, sendPasswordResetEmail, sendVerificationEmail } = require('./email-template')
const roleName = require('../constants/role')


const authenticate = async({ email, password, ipAddress }) => {
    const account = await global.db.Account.findOne({ email });

    if (!account || !account.isVerified || !bcrypt.compareSync(password, account.passwordHash)) {
        throw 'Email or password is incorrect';
    }

    // authentication successful so generate jwt and refresh tokens
    const jwtToken = generateJwtToken(account);
    const refreshToken = generateRefreshToken(account, ipAddress);

    // save refresh token
    await refreshToken.save();

    // return basic details and tokens
    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

function generateJwtToken(account) {
    // create a jwt token containing the account id that expires in 15 minutes
    return jwt.sign({ sub: account.id, id: account.id }, config.get('secret'), { expiresIn: '15m' });
}

function generateRefreshToken(account, ipAddress) {
    // create a refresh token that expires in 7 days
    return new global.db.RefreshToken({
        account: account.id,
        token: randomTokenCryptoString(),
        expires: new Date(Date.now() + 7*24*60*60*1000),
        createdByIp: ipAddress
    });
}

function randomTokenCryptoString() {
    return crypto.randomBytes(40).toString('hex');
}

function basicDetails(account) {
    const { id, title, firstName, lastName, email, role, created, updated, isVerified } = account;
    return { id, title, firstName, lastName, email, role, created, updated, isVerified };
}

const refreshToken = async({ token, ipAddress }) => {
    const refreshToken = await getRefreshToken(token);
    const { account } = refreshToken; // Destructing Object

    // replace old refresh token with a new one and save
    const newRefreshToken = generateRefreshToken(account, ipAddress);
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    refreshToken.replacedByToken = newRefreshToken.token;
    await refreshToken.save();
    await newRefreshToken.save();

    // generate new jwt
    const jwtToken = generateJwtToken(account);

    // return basic details and tokens
    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: newRefreshToken.token
    };
}

async function getRefreshToken(token) {
    const refreshToken = await global.db.RefreshToken.findOne({ token }).populate('account');
    if (!refreshToken || !refreshToken.isActive) throw 'Invalid token';
    return refreshToken;
}

async function revokeToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);

    // revoke token and save
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    await refreshToken.save();
}

const register = async(params, origin) => {
    // validate
    if (await global.db.Account.findOne({ email: params.email })) {
        // send already registered error in email to prevent account enumeration
        return await sendAlreadyRegisteredEmail(params.email, origin);
    }
        // create account object
        const account = new global.db.Account(params);

        // first registered account is an admin
        const isFirstAccount = (await global.db.Account.countDocuments({})) === 0;
        account.role = isFirstAccount ? roleName.Admin : roleName.User;
        account.verificationToken = randomTokenCryptoString();
    
        // hash password
        account.passwordHash = hash(params.password);
    
        // save account
        await account.save();
    
        // send email
        await sendVerificationEmail(account, origin);
        return;
}

const verifyEmail = async({ token }) => {
    const account = await global.db.Account.findOne({ verificationToken: token });

    if (!account) throw 'Verification failed';

    account.verified = Date.now();
    account.verificationToken = undefined;
    await account.save();
}

 const forgotPassword = async({ email }, origin) => {
    const account = await db.Account.findOne({ email });

    // always return ok response to prevent email enumeration
    if (!account) return;

    // create reset token that expires after 24 hours
    account.resetToken = {
        token: randomTokenCryptoString(),
        expires: new Date(Date.now() + 24*60*60*1000)
    };
    await account.save();

    // send email
    await sendPasswordResetEmail(account, origin);
}

 const validateResetToken = async({ token }) => {
    const account = await global.db.Account.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!account) throw 'Invalid token';
}

const resetPassword = async({ token, password }) => {
    const account = await global.db.Account.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!account) throw 'Invalid token';

    // update password and remove reset token
    account.passwordHash = hash(password);
    account.passwordReset = Date.now();
    account.resetToken = undefined;
    await account.save();
}

function hash(password) {
    return bcrypt.hashSync(password, 10);
}

const getAll = async() =>{
    const accounts = await global.db.Account.find();
    return accounts.map(x => basicDetails(x));
}

const getById = async(id) => {
    const account = await getAccount(id);
    return basicDetails(account);
}

async function getAccount(id) {
    if (!global.db.isValidId(id)) throw 'Account not found';
    const account = await global.db.Account.findById(id);
    if (!account) throw 'Account not found';
    return account;
}

const create = async (params) => {
    // validate
    if (await global.db.Account.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already registered';
    }

    const account = new global.db.Account(params);
    account.verified = Date.now();

    // hash password
    account.passwordHash = hash(params.password);

    // save account
    await account.save();

    return basicDetails(account);
}

const update = async(id, params) => {
    const account = await getAccount(id);

    // validate (if email was changed)
    if (params.email && account.email !== params.email && await global.db.Account.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already taken';
    }

    // hash password if it was entered
    if (params.password) {
        params.passwordHash = hash(params.password);
    }

    // copy params to account and save
    Object.assign(account, params);
    account.updated = Date.now();
    await account.save();

    return basicDetails(account);
}

const _delete = async(id) =>{
    const account = await getAccount(id);
    await account.remove();
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