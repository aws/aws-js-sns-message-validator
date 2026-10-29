var chai = require('chai'),
    crypto = require('crypto'),
    https = require('https'),
    pem = require('pem'),
    expect = chai.expect,
    MessageValidator = require('../index.js'),
    signableKeys = [
        'Message',
        'MessageId',
        'Subject',
        'Timestamp',
        'TopicArn',
        'Type'
    ];

function buildStringToSign(message) {
    var stringToSign = '';

    for (var i = 0; i < signableKeys.length; i++) {
        if (signableKeys[i] in message) {
            stringToSign += signableKeys[i] + "\n"
                + message[signableKeys[i]] + "\n";
        }
    }

    return stringToSign;
}

describe('End-to-end validation', function () {
    "use strict";

    var certificate,
        certificateRequests = 0,
        originalCa,
        server;

    before(function (done) {
        pem.createCertificate({
            altNames: ['127.0.0.1'],
            commonName: '127.0.0.1',
            days: 1,
            selfSigned: true
        }, function (err, certHash) {
            if (err) {
                done(err);
                return;
            }

            certificate = certHash;
            originalCa = https.globalAgent.options.ca;
            https.globalAgent.options.ca = certificate.certificate;

            server = https.createServer({
                cert: certificate.certificate,
                key: certificate.serviceKey
            }, function (req, res) {
                if (req.url !== '/cert.pem') {
                    res.writeHead(404);
                    res.end();
                    return;
                }

                certificateRequests++;
                res.writeHead(200, {'Content-Type': 'application/x-pem-file'});
                res.end(certificate.certificate);
            });
            server.listen(0, '127.0.0.1', done);
        });
    });

    after(function (done) {
        if (originalCa === undefined) {
            delete https.globalAgent.options.ca;
        } else {
            https.globalAgent.options.ca = originalCa;
        }
        server.close(done);
    });

    it('rejects a forged message with the same signed bytes', function (done) {
        var address = server.address(),
            certUrl = 'https://127.0.0.1:' + address.port + '/cert.pem',
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
                SigningCertURL: certUrl
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
                SigningCertURL: certUrl
            },
            signer = crypto.createSign('RSA-SHA256'),
            hostPattern = new RegExp('^127\\.0\\.0\\.1:'
                + address.port + '$'),
            validator = new MessageValidator(hostPattern);

        expect(buildStringToSign(collisionMessage))
            .to.equal(buildStringToSign(forgedMessage));

        signer.update(buildStringToSign(collisionMessage), 'utf8');
        collisionMessage.Signature = signer.sign(
            certificate.serviceKey,
            'base64'
        );
        forgedMessage.Signature = collisionMessage.Signature;

        validator.validate(collisionMessage, function (err, message) {
            if (err) {
                done(err);
                return;
            }

            try {
                expect(message).to.equal(collisionMessage);
                expect(certificateRequests).to.equal(1);
            } catch (e) {
                done(e);
                return;
            }

            validator.validate(forgedMessage, function (forgedErr) {
                try {
                    expect(forgedErr).to.be.an.instanceof(Error);
                    expect(forgedErr.message)
                        .to.equal('The message Type is not supported.');
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });
    });
});
