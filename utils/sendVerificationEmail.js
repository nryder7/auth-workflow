const sendEmail = require('./sendEmail');

const sendVerificationEmail = async ({
  name,
  email,
  verificationToken,
  origin,
}) => {
  const verifyEmailLink = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`;

  const message = `<p>Please confirm your email by clicking on following link:</p><a href="${verifyEmailLink}">Verify Email </a></p>`;

  return sendEmail({
    to: email,
    subject: 'Email verification',
    html: `<h4>Hello, ${name}</h4>${message}`,
  });
};
module.exports = sendVerificationEmail;
