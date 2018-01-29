var chai = require('chai'),
    crypto = require('crypto'),
    sandbox = require('sinon').sandbox.create(),
    expect = chai.expect,
    should = chai.should,
    rewire = require('rewire'),
    pem = require('pem'),
    _ = require('underscore'),
    MessageValidator = rewire('../index.js'),
    signableKeysForSubscription = MessageValidator.__get__('signableKeysForSubscription'),
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
    utf8Message = _.extend({}, validMessage, {
        Message: 'Ａ Ｍｅｓｓａｇｅ Ｆｏｒ ｙｏｕ！',
    }),
    utf8SubscriptionControlMessage = _.extend({}, utf8Message, {
        Token: 'Nonce',
        SubscribeURL: 'https://www.amazonaws.com',
        Type: 'SubscriptionConfirmation'
    }),
    validCertUrl = 'https://sns.us-east-1.amazonaws.com/cert.pem';

describe('Message Validator', function () {
    "use strict";

    before(function (done) {
        pem.createCertificate({}, function (err, certHash) {
            if (err) throw err;

            var crypto = require('crypto'),
                validMessages = [
                    validMessage,
                    validLambdaMessage,
                    validSubscriptionControlMessage,
                    utf8Message,
                    utf8SubscriptionControlMessage
                ];

            for (var i = 0; i < validMessages.length; i++) {
                var signer = crypto.createSign('RSA-SHA1');

                for (var j = 0; j < signableKeysForSubscription.length; j++) {
                    if (signableKeysForSubscription[j] in validMessages[i]) {
                        // skip signing null Subject fields to match Lambda behavior
                        if (
                            signableKeysForSubscription[j] === 'Subject' &&
                            validMessages[i][signableKeysForSubscription[j]] === null
                        ) {
                            continue;
                        }

                        signer.update(signableKeysForSubscription[j] + "\n"
                            + validMessages[i][signableKeysForSubscription[j]] + "\n", 'utf8');
                    }
                }

                validMessages[i]['Signature']
                    = signer.sign(certHash.serviceKey, 'base64');
            }

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
                    SignatureVersion: '2',
                    SigningCertURL: validCertUrl
                }), function (err, message) {
                    if (!err) {
                        done(new Error('The validator should not have accepted this message.'));
                    }

                    try {
                        expect(err.message)
                            .to.equal('The signature version 2 is not supported.');
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
