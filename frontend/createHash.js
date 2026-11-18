const bcrypt = require('bcryptjs');

async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

async function checkPassword(password, storedHash) {
  return bcrypt.compare(password, storedHash);
}

module.exports = { hashPassword, checkPassword };