const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const schema = new Schema({
  email: {
    type: String,
    unique: true,
    required: true,
  },
  passwordHash: {
    type: String,
    required: true,
  },
  title: {
    type: String,
    required: true,
  },
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  acceptTerms: Boolean,
  role: {
    type: String,
    required: true,
  },
  verificationToken: String,
  verified: Date,
  resetToken: {
    token: String,
    expires: Date,
  },
  passwordReset: Date
},{
    timestamps: true
});

schema.virtual("isVerified").get(function () {
  return !!(this.verified || this.passwordReset);
});

// schema.set('toJSON', { ... }); configures which account properties are included when converting MongoDB records to JSON objects:
schema.set("toJSON", {
  virtuals: true,
  versionKey: false,
  transform: function (doc, ret) {
    // remove these props when object is serialized
    delete ret._id;
    delete ret.passwordHash;
  },
});

// virtuals: true includes the Mongoose virtual id property which is a copy of the MongoDB _id property.
// versionKey: false excludes the Mongoose version key (__v).
// transform: function (doc, ret) { ... } removes the MongoDB _id and passwordHash properties when converting records to JSON.
module.exports = mongoose.model("Account", schema);
