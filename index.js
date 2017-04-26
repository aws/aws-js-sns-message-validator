"use strict";

var url = require('url'),
    https = require('https'),
    crypto = require('crypto'),
    isNil = require('lodash.isnil'),
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
    ];

var hashHasKey = function (hash, key) {
    if (!(key in hash)) {
        if (/URL$/.test(key) && key.replace(/URL$/, 'Url') in hash) {
            return true;
        }
        return false;
    }
    return true;
};

var hashHasKeys = function (hash, keys) {
    for (var i = 0; i < keys.length; i++) {
        if (!hashHasKey(hash, keys[i])) {
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

var getCertificate = function (certUrl, cb) {
    if (certCache.hasOwnProperty(certUrl)) {
        cb(null, certCache[certUrl]);
        return;
    }

    https.get(certUrl, function (res) {
        var chunks = [];

        if(res.statusCode !== 200){
            return cb(new Error('Certificate could not be retrieved'));
        }

        res
            .on('data', function (data) {
                chunks.push(data.toString());
            })
            .on('end', function () {
                certCache[certUrl] = chunks.join('');
                cb(null, certCache[certUrl]);
            });
    }).on('error', cb)
};

var validateSignature = function (message, cb, encoding) {
    if (message['SignatureVersion'] !== '1') {
        cb(new Error('The signature version '
            + message['SignatureVersion'] + ' is not supported.'));
        return;
    }

    var signableKeys = [];
    if (message.Type === 'SubscriptionConfirmation') {
        signableKeys = signableKeysForSubscription.slice(0);
    } else {
        signableKeys = signableKeysForNotification.slice(0);
    }

    var verifier = crypto.createVerify('RSA-SHA1');
    for (var i = 0; i < signableKeys.length; i++) {
        if (signableKeys[i] in message && !isNil(message[signableKeys[i]])) {
            verifier.update(signableKeys[i] + "\n"
                + message[signableKeys[i]] + "\n", encoding);
        }
    }

    const certificateUrl = message.SigningCertURL || message.SigningCertUrl;
    getCertificate(certificateUrl, function (err, certificate) {
        if (err) {
            cb(err);
            return;
        }
        try {
            if (verifier.verify(certificate, message['Signature'], 'base64')) {
                cb(null, message);
            } else {
                cb(new Error('The message signature is invalid.'));
            }
        } catch (e) {
            cb(e);
        }
    });
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
 * @param {validationCallback} cb
 */
MessageValidator.prototype.validate = function (hash, cb) {
    var hostPattern = this.hostPattern;

    if (!validateMessageStructure(hash)) {
        cb(new Error('Message missing required keys.'));
        return;
    }

    if (!validateUrl(hash['SigningCertURL'] || hash['SigningCertUrl'], hostPattern)) {
        cb(new Error('The certificate is located on an invalid domain.'));
        return;
    }

    validateSignature(hash, cb, this.encoding);
};

module.exports = MessageValidator;
