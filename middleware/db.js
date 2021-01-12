const config = require('config');
const mongoose = require('mongoose');
const connectionOptions = { useCreateIndex: true, useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false };
mongoose.connect(config.get('database.host'), config.get('database.mongo_options') || connectionOptions)
.then(() => {
    console.log("DB CONNECTED");
}).catch( (error) =>{
    console.log("Error occured in DB", error)}
);;
mongoose.Promise = global.Promise;
module.exports = {
    Account: require('../models/user-account'),
    RefreshToken: require('../models/refresh-token'),
    isValidId
};

function isValidId(id) {
    return mongoose.Types.ObjectId.isValid(id);
}



