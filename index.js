"use strict";

var url = require('url'),
    https = require('https'),
    crypto = require('crypto'),
    defaultEncoding = 'utf8',
    defaultHostPattern = /^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$/,
    certCache = {},
    supportedMessageTypes = [
        'Notification',
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
    signableKeysByType = {
        'Notification': [
            'Message',
            'MessageId',
            'Subject',
            'Timestamp',
            'TopicArn',
            'Type'
        ],
        'SubscriptionConfirmation': [
            'Message',
            'MessageId',
            'SubscribeURL',
            'Timestamp',
            'Token',
            'TopicArn',
            'Type'
        ],
        'UnsubscribeConfirmation': [
            'Message',
            'MessageId',
            'SubscribeURL',
            'Timestamp',
            'Token',
            'TopicArn',
            'Type'
        ]
    },
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
    if (!hashHasKeys(message, requiredKeys)) {
        return false;
    }

    var signableKeys = signableKeysByType[message['Type']];
    for (var i = 0; i < signableKeys.length; i++) {
        if (signableKeys[i] !== 'Subject' && !(signableKeys[i] in message)) {
            return false;
        }
    }

    return true;
};

var validateSignedValues = function (message) {
    var signableKeys = signableKeysByType[message['Type']];

    for (var i = 0; i < signableKeys.length; i++) {
        var key = signableKeys[i];
        if (key in message
            && key !== 'Message'
            && key !== 'Subject'
            && /[\r\n]/.test(message[key])) {
            return key;
        }
    }

    return null;
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
    var signatureVersion = message['SignatureVersion'];
    if (signatureVersion !== '1' && signatureVersion !== '2') {
        cb(new Error('The signature version '
            + signatureVersion + ' is not supported.'));
        return;
    }

    var signableKeys = signableKeysByType[message.Type];

    var verifier = (signatureVersion === '1') ? crypto.createVerify('RSA-SHA1') : crypto.createVerify('RSA-SHA256');
    for (var i = 0; i < signableKeys.length; i++) {
        if (signableKeys[i] in message) {
            verifier.update(signableKeys[i] + "\n"
                + message[signableKeys[i]] + "\n", encoding);
        }
    }

    getCertificate(message['SigningCertURL'], function (err, certificate) {
        if (err) {
            cb(err);
            return;
        }
        try {
            if (!verifier.verify(certificate, message['Signature'], 'base64')) {
                throw new Error('The message signature is invalid.');
            }
        } catch (e) {
            cb(e);
            return;
        }
        cb(null, message);
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
    if (typeof hash === 'string') {
        try {
            hash = JSON.parse(hash);
        } catch (err) {
            cb(err);
            return;
        }
    }

    hash = convertLambdaMessage(hash);

    if (!hashHasKeys(hash, ['Type'])) {
        cb(new Error('Message missing required keys.'));
        return;
    }

    if (indexOf(supportedMessageTypes, hash['Type']) === -1) {
        cb(new Error('The message Type is not supported.'));
        return;
    }

    if (!validateMessageStructure(hash)) {
        cb(new Error('Message missing required keys.'));
        return;
    }

    var fieldWithNewline = validateSignedValues(hash);
    if (fieldWithNewline !== null) {
        cb(new Error('The message field "' + fieldWithNewline
            + '" must not contain newlines.'));
        return;
    }

    if (!validateUrl(hash['SigningCertURL'], this.hostPattern)) {
        cb(new Error('The certificate is located on an invalid domain.'));
        return;
    }

    validateSignature(hash, cb, this.encoding);
};

module.exports = MessageValidator;
