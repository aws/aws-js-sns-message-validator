"use strict";

var URL = require('url').URL,
    https = require('https'),
    crypto = require('crypto'),
    defaultEncoding = 'utf8',
    defaultHostPattern = /^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$/,
    certCache = {},
    maxCertificateSize = 64 * 1024,
    certificateRequestTimeout = 10000,
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

// Returns the canonical SigningCertURL to fetch, or null if invalid.
var validateUrl = function (urlToValidate, hostPattern) {
    if (typeof urlToValidate !== 'string') {
        return null;
    }

    var parsed;
    try {
        parsed = new URL(urlToValidate);
    } catch (e) {
        return null;
    }

    if (parsed.protocol !== 'https:'
        || parsed.username !== ''
        || parsed.password !== ''
        || parsed.search !== ''
        || parsed.hash !== ''
        || parsed.pathname.substr(-4) !== '.pem'
        || !hostPattern.test(parsed.host)) {
        return null;
    }

    return parsed.href;
};

var getCertificate = function (certUrl, cb) {
    if (certCache.hasOwnProperty(certUrl)) {
        cb(null, certCache[certUrl]);
        return;
    }

    var finished = false,
        done = function (err, certificate) {
            if (finished) {
                return;
            }
            finished = true;
            cb(err, certificate);
        },
        req;

    try {
        req = https.get(certUrl, function (res) {
            var chunks = [],
                size = 0;

            if (res.statusCode !== 200) {
                res.resume();
                return done(new Error('Certificate could not be retrieved'));
            }

            res
                .on('data', function (data) {
                    size += data.length;
                    if (size > maxCertificateSize) {
                        req.destroy();
                        done(new Error('Certificate could not be retrieved'));
                        return;
                    }
                    chunks.push(data);
                })
                .on('end', function () {
                    if (finished) {
                        return;
                    }
                    var certificate = Buffer.concat(chunks).toString();
                    certCache[certUrl] = certificate;
                    done(null, certificate);
                })
                .on('error', done);
        });
    } catch (e) {
        done(e);
        return;
    }

    req.on('error', done);
    req.setTimeout(certificateRequestTimeout, function () {
        req.destroy();
        done(new Error('Certificate could not be retrieved'));
    });
};

var validateSignature = function (message, certUrl, cb, encoding) {
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

    getCertificate(certUrl, function (err, certificate) {
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

    var certUrl = validateUrl(hash['SigningCertURL'], this.hostPattern);
    if (certUrl === null) {
        cb(new Error('The certificate is located on an invalid domain.'));
        return;
    }

    validateSignature(hash, certUrl, cb, this.encoding);
};

module.exports = MessageValidator;
