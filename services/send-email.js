const nodemailer = require('nodemailer');
const config = require('config');


const sendEmail = async ({ to, subject, html, from = config.get('email_config.emailFrom') }) =>{
    const transporter = nodemailer.createTransport(config.get('email_config.smtpOptions'));
    await transporter.sendMail({ from, to, subject, html });
    return;
}
module.exports = {
    sendEmail
};