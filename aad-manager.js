'use strict';

const bunyan = require('bunyan');
const msRestAzure = require('ms-rest-azure');
const graphRbacManagementClient = require('azure-graph');
const boxManager = require('./box-manager');

const log = bunyan.createLogger({
    name: 'aad-manager'
});

const login = function (oid) {
    msRestAzure.loginWithServicePrincipalSecret(process.env.AAD_CLIENT_ID, process.env.AAD_CLIENT_SECRET, process.env.AAD_TENANT_ID, { tokenAudience: 'graph' },
        function (err, credentials, subscriptions) {
            if (err) log.error(err);
            var client = new graphRbacManagementClient(credentials, process.env.AAD_TENANT_ID);
            client.users.get(oid, function (err, result, request, response) {
                // create Box app user if property 'immutableId' is not set in Azure AD for the logged in user. 
                if (!result.immutableId) {
                    boxManager.createAppUser(oid);

                    var userParams = {
                        immutableId: oid,
                    };
                    // update logged in user's property 'immutableId' in Azure AD. 
                    client.users.update(oid, userParams, function (err, result, request, response) {
                        if (err) log.error(err);
                    });
                }
            });
        });
};

module.exports = {
    login
};
