'use strict';

const fs = require('fs');
const Box = require('box-node-sdk');

const privateKeyPath = `${process.env.PRIVATE_KEY_ROOT}/private_key.pem`;
const privateKey = fs.readFileSync(privateKeyPath);

const BoxSdk = new Box({
    clientID: process.env.BOX_CLIENT_ID,
    clientSecret: process.env.BOX_CLIENT_SECRET,
    appAuth: {
        keyID: process.env.BOX_PUBLIC_KEY_ID,
        privateKey: privateKey,
        passphrase: process.env.BOX_PRIVATE_KEY_PASSWORD
    }
});

const createAppUser = function (userName) {
    var requestParams = {
        body: {
            name: userName,
            is_platform_access_only: true
        }
    };

    //Get App auth client
    const boxAdminClient = BoxSdk.getAppAuthClient('enterprise', process.env.BOX_ENTERPRISE_ID);
    return new Promise(function (resolve, reject) {
        //Create the user in Box
        boxAdminClient.post('/users', requestParams, boxAdminClient.defaultResponseHandler(function (error, boxResponse) {
            if (error) {
                reject(error);
            }

            resolve(boxResponse);
        }));
    });
};

module.exports = {
    createAppUser
};
