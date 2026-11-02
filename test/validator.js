var chai = require('chai'),
    crypto = require('crypto'),
    sandbox = require('sinon').sandbox.create(),
    expect = chai.expect,
    should = chai.should,
    rewire = require('rewire'),
    pem = require('pem'),
    _ = require('underscore'),
    MessageValidator = rewire('../index.js'),
    signableKeysByType = MessageValidator.__get__('signableKeysByType'),
    invalidMessage = {
        foo: 'bar',
        fizz: 'buzz'
    },
    validMessage = {
        Type: 'Notification',
        MessageId: '1',
        TopicArn: 'arn',
        Message: 'A message for you!',
        Timestamp: (new Date).toISOString(),
        SignatureVersion: '1',
        SigningCertURL: "https://localhost:56789/cert.pem"
    },
    validSHA256Message = {
        Type: 'Notification',
        MessageId: '1',
        TopicArn: 'arn',
        Message: 'A message for you!',
        Timestamp: (new Date).toISOString(),
        SignatureVersion: '2',
        SigningCertURL: "https://localhost:56789/cert.pem"
    },
    validLambdaMessage = {
        Type: 'Notification',
        MessageId: '1',
        TopicArn: 'arn',
        Subject: null,
        Message: 'A Lambda message for you!',
        Timestamp: (new Date).toISOString(),
        SignatureVersion: '1',
        SigningCertUrl: "https://localhost:56789/cert.pem"
    },
    validSubscriptionControlMessage = _.extend({}, validMessage, {
        Token: 'Nonce',
        SubscribeURL: 'https://www.amazonaws.com',
        Type: 'SubscriptionConfirmation'
    }),
    validUnsubscriptionControlMessage = _.extend(
        {},
        validSubscriptionControlMessage,
        {Type: 'UnsubscribeConfirmation'}
    ),
    utf8Message = _.extend({}, validMessage, {
        Message: 'Ａ Ｍｅｓｓａｇｅ Ｆｏｒ ｙｏｕ！',
    }),
    utf8SubscriptionControlMessage = _.extend({}, utf8Message, {
        Token: 'Nonce',
        SubscribeURL: 'https://www.amazonaws.com',
        Type: 'SubscriptionConfirmation'
    }),
    multilineMessage = _.extend({}, validMessage, {
        Message: "first\nsecond",
        Subject: "first\nsecond"
    }),
    forgedMessage = {
        Type: 'MessageId\nattacker-message-id'
            + '\nTimestamp\n2015-10-05T06:41:38.000Z'
            + '\nTopicArn\narn:aws:sns:us-east-1:999999999999:attacker'
            + '\nType\nNotification',
        MessageId: 'forged-message-id',
        TopicArn: 'arn:aws:sns:us-east-1:111111111111:victim',
        Message: 'perform protected action',
        Timestamp: '2015-10-05T06:40:38.000Z',
        SignatureVersion: '2',
        SigningCertURL: "https://localhost:56789/cert.pem"
    },
    collisionMessage = {
        Type: 'Notification',
        MessageId: 'attacker-message-id',
        TopicArn: 'arn:aws:sns:us-east-1:999999999999:attacker',
        Message: 'perform protected action'
            + '\nMessageId\nforged-message-id'
            + '\nTimestamp\n2015-10-05T06:40:38.000Z'
            + '\nTopicArn\narn:aws:sns:us-east-1:111111111111:victim'
            + '\nType',
        Timestamp: '2015-10-05T06:41:38.000Z',
        SignatureVersion: '2',
        SigningCertURL: "https://localhost:56789/cert.pem"
    },
    validCertUrl = 'https://sns.us-east-1.amazonaws.com/cert.pem';

function buildStringToSign(message, signableKeys) {
    var stringToSign = '';

    for (var i = 0; i < signableKeys.length; i++) {
        if (signableKeys[i] in message) {
            stringToSign += signableKeys[i] + "\n"
                + message[signableKeys[i]] + "\n";
        }
    }

    return stringToSign;
}

describe('Message Validator', function () {
    "use strict";

    before(function (done) {
        pem.createCertificate({}, function (err, certHash) {
            if (err) throw err;

            var crypto = require('crypto'),
                validMessages = [
                    validMessage,
                    validSHA256Message,
                    validLambdaMessage,
                    validSubscriptionControlMessage,
                    validUnsubscriptionControlMessage,
                    utf8Message,
                    utf8SubscriptionControlMessage,
                    multilineMessage,
                    collisionMessage
                ];

            for (var i = 0; i < validMessages.length; i++) {
                var signatureVersion = validMessages[i]['SignatureVersion'];
                var signer = (signatureVersion === '1') ? crypto.createSign('RSA-SHA1') : crypto.createSign('RSA-SHA256');
                var signableKeys = signableKeysByType[validMessages[i]['Type']];

                for (var j = 0; j < signableKeys.length; j++) {
                    if (signableKeys[j] in validMessages[i]) {
                        // skip signing null Subject fields to match Lambda behavior
                        if (
                            signableKeys[j] === 'Subject' &&
                            validMessages[i][signableKeys[j]] === null
                        ) {
                            continue;
                        }

                        signer.update(signableKeys[j] + "\n"
                            + validMessages[i][signableKeys[j]] + "\n", 'utf8');
                    }
                }

                validMessages[i]['Signature']
                    = signer.sign(certHash.serviceKey, 'base64');
            }
            forgedMessage.Signature = collisionMessage.Signature;

            MessageValidator.__set__('getCertificate', function (url, cb) {
                cb(null, certHash.certificate);
            });
            done();
        });
    });

    afterEach(function () {
        sandbox.restore();
    });

    describe('validator interface', function () {
        it('should call the provided callback with the validated message', function (done) {
            (new MessageValidator(/^localhost:56789$/))
                .validate(validMessage, function (err, message) {
                    if (err) {
                        done(err);
                        return;
                    }

                    try {
                        expect(message).to.equal(validMessage);
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
        });
    });

    describe('message validation', function () {
        it('should reject hashes without all required keys', function (done) {
            (new MessageValidator)
                .validate(invalidMessage, function (err, message) {
                    if (!err) {
                        done(new Error('The validator should not have accepted this message.'));
                    }

                    try {
                        expect(err.message)
                            .to.equal('Message missing required keys.');
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
        });

        it('should reject canonical string collisions', function (done) {
            expect(buildStringToSign(
                collisionMessage,
                signableKeysByType['Notification']
            )).to.equal(buildStringToSign(
                forgedMessage,
                signableKeysByType['Notification']
            ));

            (new MessageValidator(/^localhost:56789$/))
                .validate(forgedMessage, function (err, message) {
                    if (!err) {
                        done(new Error('The validator should not have accepted this message.'));
                    }

                    try {
                        expect(err.message)
                            .to.equal('The message Type is not supported.');
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
        });

        it('should accept Lambda payloads with improper "Url" casing', function (done) {
            (new MessageValidator(/^localhost:56789$/))
                .validate(validLambdaMessage, function (err, message) {
                    if (err) {
                        return done(new Error('The validator should have accepted this message.'));
                    }

                    try {
                        expect(message.Message)
                            .to.equal('A Lambda message for you!');
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
        });

        it('should reject hashes residing on an invalid domain', function (done) {
            (new MessageValidator)
                .validate(validMessage, function (err, message) {
                    if (!err) {
                        done(new Error('The validator should not have accepted this message.'));
                    }

                    try {
                        expect(err.message)
                            .to.equal('The certificate is located on an invalid domain.');
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
        });

        it('should reject hashes with an invalid signature type', function (done) {
            (new MessageValidator)
                .validate(_.extend({}, validMessage, {
                    SignatureVersion: '3',
                    SigningCertURL: validCertUrl
                }), function (err, message) {
                    if (!err) {
                        done(new Error('The validator should not have accepted this message.'));
                    }

                    try {
                        expect(err.message)
                            .to.equal('The signature version 3 is not supported.');
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
        });

        it('should attempt to verify the signature of well-structured messages', function (done) {
            (new MessageValidator(/^localhost:56789$/))
                .validate(_.extend({}, validMessage, {
                    Signature: (new Buffer('NOT A VALID SIGNATURE'))
                        .toString('base64')
                }), function (err, message) {
                    if (!err) {
                        done(new Error('The validator should not have accepted this message.'));
                    }

                    try {
                        expect(err.message)
                            .to.equal('The message signature is invalid.');
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
        });

        it('should accept a valid message', function (done) {
            (new MessageValidator(/^localhost:56789$/))
                .validate(validMessage, done);
        });

        it('should accept a valid message', function (done) {
            (new MessageValidator(/^localhost:56789$/))
                .validate(validSHA256Message, done);
        });

        it('should ignore subscription fields on notifications', function (done) {
            (new MessageValidator(/^localhost:56789$/))
                .validate(_.extend({}, validMessage, {
                    SubscribeURL: 'https://www.amazonaws.com',
                    Token: 'not-signed'
                }), done);
        });

        it('should allow newlines in message and subject', function (done) {
            (new MessageValidator(/^localhost:56789$/))
                .validate(multilineMessage, done);
        });

        it('should accept valid messages as JSON strings', function (done) {
            (new MessageValidator(/^localhost:56789$/))
                .validate(JSON.stringify(validMessage), done);
        });
    });

    describe('subscription control message validation', function () {
        it('should reject subscribe hashes without additional keys', function (done) {
            (new MessageValidator(/^localhost:56789$/))
                .validate(_.extend({}, validMessage, {
                    Type: 'SubscriptionConfirmation'
                }), function (err, message) {
                    if (!err) {
                        done(new Error('The validator should not have accepted this message.'));
                    }

                    try {
                        expect(err.message)
                            .to.equal('Message missing required keys.');
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
        });

        it('should accept a valid subscription control message', function (done) {
            (new MessageValidator(/^localhost:56789$/))
                .validate(validSubscriptionControlMessage, done);
        });

        it('should accept a valid unsubscribe control message', function (done) {
            (new MessageValidator(/^localhost:56789$/))
                .validate(validUnsubscriptionControlMessage, done);
        });

        it('should ignore subject fields on subscription messages', function (done) {
            (new MessageValidator(/^localhost:56789$/))
                .validate(_.extend({}, validSubscriptionControlMessage, {
                    Subject: 'not-signed'
                }), done);
        });

        [
            ['MessageId', "value\ninjection"],
            ['Timestamp', "value\rinjection"],
            ['TopicArn', "value\ninjection"]
        ].forEach(function (testCase) {
            it('should reject newlines in ' + testCase[0], function (done) {
                var message = _.extend({}, validMessage);
                message[testCase[0]] = testCase[1];

                (new MessageValidator(/^localhost:56789$/))
                    .validate(message, function (err) {
                        try {
                            expect(err.message).to.equal(
                                'The message field "' + testCase[0]
                                    + '" must not contain newlines.'
                            );
                            done();
                        } catch (e) {
                            done(e);
                        }
                    });
            });
        });

        [
            ['SubscribeURL', "value\ninjection"],
            ['Token', "value\rinjection"]
        ].forEach(function (testCase) {
            it('should reject newlines in ' + testCase[0], function (done) {
                var message = _.extend({}, validSubscriptionControlMessage);
                message[testCase[0]] = testCase[1];

                (new MessageValidator(/^localhost:56789$/))
                    .validate(message, function (err) {
                        try {
                            expect(err.message).to.equal(
                                'The message field "' + testCase[0]
                                    + '" must not contain newlines.'
                            );
                            done();
                        } catch (e) {
                            done(e);
                        }
                    });
            });
        });
    });

    describe('UTF8 message validation', function () {
        it('should accept a valid UTF8 message', function (done) {
            (new MessageValidator(/^localhost:56789$/, 'utf8'))
                .validate(utf8Message, done);
        });
    });

    describe('invalid signing cert', function () {
        it('should catch any errors thrown during verification', function (done) {
            var verifier = {
                update: sandbox.spy(),
                verify: sandbox.stub().throws()
            };
            sandbox.stub(crypto, 'createVerify').returns(verifier);

            (new MessageValidator(/^localhost:56789$/, 'utf8'))
                .validate(utf8Message, function (err, result) {
                    expect(err).not.to.be.undefined;
                    expect(result).to.be.undefined;
                    done();
                });
        });
    });
});
