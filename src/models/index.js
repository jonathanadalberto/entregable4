const EmailCode = require("./EmailCode");
const User = require("./User");

EmailCode.belongsTo(User); //userId
User.hasOne(EmailCode);