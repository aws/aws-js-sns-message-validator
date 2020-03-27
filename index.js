"use strict";

var url = require('url'),
    https = require('https'),
    crypto = require('crypto'),
    defaultEncoding = 'utf8',
    defaultHostPattern = /^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$/,
    certCache = {},
    subscriptionControlKeys = ['SubscribeURL', 'Token'],
    subscriptionControlMessageTypes = [
        'SubscriptionConfirmation',
        'UnsubscribeConfirmation'
    ],
    requiredKeys = [
        'Message',
        'MessageId',
        'Timestamp',
        'TopicArn',
        'Type',
        'Signature',
        'SigningCertURL',
        'SignatureVersion'
    ],
    signableKeysForNotification = [
        'Message',
        'MessageId',
        'Subject',
        'SubscribeURL',
        'Timestamp',
        'TopicArn',
        'Type'
    ],
    signableKeysForSubscription = [
        'Message',
        'MessageId',
        'Subject',
        'SubscribeURL',
        'Timestamp',
        'Token',
        'TopicArn',
        'Type'
    ],
    lambdaMessageKeys = {
        'SigningCertUrl': 'SigningCertURL',
        'UnsubscribeUrl': 'UnsubscribeURL'
    };

var hashHasKeys = function (hash, keys) {
    for (var i = 0; i < keys.length; i++) {
        if (!(keys[i] in hash)) {
            return false;
        }
    }

    return true;
};

var indexOf = function (array, value) {
    for (var i = 0; i < array.length; i++) {
        if (value === array[i]) {
            return i;
        }
    }

    return -1;
};

function convertLambdaMessage(message) {
    for (var key in lambdaMessageKeys) {
        if (key in message) {
            message[lambdaMessageKeys[key]] = message[key];
        }
    }

    if ('Subject' in message && message.Subject === null) {
        delete message.Subject;
    }

    return message;
}

var validateMessageStructure = function (message) {
    var valid = hashHasKeys(message, requiredKeys);

    if (indexOf(subscriptionControlMessageTypes, message['Type']) > -1) {
        valid = valid && hashHasKeys(message, subscriptionControlKeys);
    }

    return valid;
};

var validateUrl = function (urlToValidate, hostPattern) {
    var parsed = url.parse(urlToValidate);

    return parsed.protocol === 'https:'
        && parsed.path.substr(-4) === '.pem'
        && hostPattern.test(parsed.host);
};

var getCertificate = function (certUrl) {
    return new Promise(function (resolve, reject) {
        if (certCache.hasOwnProperty(certUrl)) {
            resolve(certCache[certUrl]);
            return;
        }

        https.get(certUrl, function (res) {
            var chunks = [];

            if(res.statusCode !== 200){
                reject(new Error('Certificate could not be retrieved'));
                return;
            }

            res
                .on('data', function (data) {
                    chunks.push(data.toString());
                })
                .on('end', function () {
                    certCache[certUrl] = chunks.join('');
                    resolve(certCache[certUrl]);
                });
        }).on('error', reject);
    });
};

var validateSignature = function (message, encoding) {
    if (message['SignatureVersion'] !== '1') {
        return Promise.reject(new Error('The signature version '
            + message['SignatureVersion'] + ' is not supported.'));
    }

    var signableKeys = [];
    if (message.Type === 'SubscriptionConfirmation') {
        signableKeys = signableKeysForSubscription.slice(0);
    } else {
        signableKeys = signableKeysForNotification.slice(0);
    }

    var verifier = crypto.createVerify('RSA-SHA1');
    for (var i = 0; i < signableKeys.length; i++) {
        if (signableKeys[i] in message) {
            verifier.update(signableKeys[i] + "\n"
                + message[signableKeys[i]] + "\n", encoding);
        }
    }

    return getCertificate(message['SigningCertURL'])
        .then(function (certificate) {
            try {
                if (verifier.verify(certificate, message['Signature'], 'base64')) {
                    return Promise.resolve(message);
                } else {
                    return Promise.reject(new Error('The message signature is invalid.'));
                }
            } catch (e) {
                return Promise.reject(new Error('The message signature is invalid.'));
            }
        })
};

/**
 * A validator for inbound HTTP(S) SNS messages.
 *
 * @constructor
 * @param {RegExp} [hostPattern=/^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$/] - A pattern used to validate that a message's certificate originates from a trusted domain.
 * @param {String} [encoding='utf8'] - The encoding of the messages being signed.
 */
function MessageValidator(hostPattern, encoding) {
    this.hostPattern = hostPattern || defaultHostPattern;
    this.encoding = encoding || defaultEncoding;
}

/**
 * A callback to be called by the validator once it has verified a message's
 * signature.
 *
 * @callback validationCallback
 * @param {Error} error - Any error encountered attempting to validate a
 *                          message's signature.
 * @param {Object} message - The validated inbound SNS message.
 */

/**
 * Validates a message's signature and passes it to the provided callback.
 *
 * @param {Object} hash
 * @param {validationCallback} cb - Optional callback, if not passed a Promise is returned.
 * @returns {Promise<Object>} - If no callback is passed, a Promise is returned.
 */
MessageValidator.prototype.validate = function (hash, cb) {
    if (typeof hash === 'string') {
        try {
            hash = JSON.parse(hash);
        } catch (err) {
            if (cb) {
                cb(err);
                return;
            }
            return Promise.reject(err);
        }
    }

    hash = convertLambdaMessage(hash);

    if (!validateMessageStructure(hash)) {
        var err = new Error('Message missing required keys.');
        if (cb) {
            cb(err);
            return;
        }
        return Promise.reject(err);
    }

    if (!validateUrl(hash['SigningCertURL'], this.hostPattern)) {
        var err = new Error('The certificate is located on an invalid domain.');
        if (cb) {
            cb(err);
            return;
        }

        return Promise.reject(err);
    }

    var result = validateSignature(hash, this.encoding);

    if (cb) {
        result
            .then(function (message) {
                cb(null, message);
            })
            .catch(function (err) {
                cb(err);
            });
        return;
    }

    return result;
};

module.exports = MessageValidator;
