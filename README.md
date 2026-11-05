# Fork of Amazon SNS Message Validator for JavaScript

This fork of [`sns-validator`](https://www.npmjs.com/package/sns-validator) uses https lib with the proxy settings.

## Amazon SNS Message Validator for JavaScript

The **Amazon SNS Message Validator for Node.js** library allows you to validate
that incoming HTTP(S) POST messages are valid Amazon SNS notifications. This
library is standalone and does not depend on the AWS SDK for JavaScript.

## Basic Usage

To validate a message, you can instantiate a `MessageValidator` object and pass
an SNS message and a callback to its `validate` method. The message should be
the result of calling `JSON.parse` on the body of the HTTP(S) message sent by
SNS to your endpoint. The callback should take two arguments, the first being
an error and the second being the successfully validated SNS message.

The message validator checks the `SigningCertURL`, `SignatureVersion`, and
`Signature` to make sure they are valid and consistent with the message data.

```javascript
var MessageValidator = require("@turbot/sns-validator"),
    validator = new MessageValidator();

validator.validate(message, function (err, message) {
    if (err) {
        // Your message could not be validated.
        return;
    }

    // message has been validated and its signature checked.
});
```

## Installation

The SNS Message Validator relies on the Node crypto module and is only designed
to work on a server, not in a browser. The validation performed is only
necessary when subscribing HTTP(S)

## About Amazon SNS

[Amazon Simple Notification Service (Amazon SNS)][sns] is a fast, fully-managed,
push messaging service. Amazon SNS can deliver messages to email, mobile devices
(i.e., SMS; iOS, Android and FireOS push notifications), Amazon SQS queues,and
— of course — HTTP/HTTPS endpoints.

With Amazon SNS, you can setup topics to publish custom messages to subscribed
endpoints. However, SNS messages are used by many of the other AWS services to
communicate information asynchronously about your AWS resources. Some examples
include:

- Configuring Amazon Glacier to notify you when a retrieval job is complete.
- Configuring AWS CloudTrail to notify you when a new log file has been written.
- Configuring Amazon Elastic Transcoder to notify you when a transcoding job
  changes status (e.g., from "Progressing" to "Complete")

Though you can certainly subscribe your email address to receive SNS messages
from service events like these, your inbox would fill up rather quickly. There
is great power, however, in being able to subscribe an HTTP/HTTPS endpoint to
receive the messages. This allows you to program webhooks for your applications
to easily respond to various events.

## Handling Messages

### Confirming a Subscription to a Topic

In order to handle a `SubscriptionConfirmation` message, you must use the
`SubscribeURL` value in the incoming message:

```javascript
var https = require("https"),
    MessageValidator = require("@turbot/sns-validator"),
    validator = new MessageValidator();

validator.validate(message, function (err, message) {
    if (err) {
        console.error(err);
        return;
    }

    if (message["Type"] === "SubscriptionConfirmation") {
        https.get(message["SubscribeURL"], function (res) {
          // You have confirmed your endpoint subscription
        });
    }
});
```

If an incoming message includes multibyte characters and its encoding is utf8,
set the encoding to `validator`.

```javascript
var MessageValidator = require("@turbot/sns-validator"),
    validator = new MessageValidator();
validator.encoding = "utf8";
```

### Receiving a Notification

To receive a notification, use the same code as the preceding example, but
check for the `Notification` message type.

```javascript
if (message["Type"] === "Notification") {
    // Do whatever you want with the message body and data.
    console.log(message["MessageId"] + ": " + message["Message"]);
}
```

The message body will be a string, and will hold whatever data was published
to the SNS topic.

### Unsubscribing

Unsubscribing looks the same as subscribing, except the message type will be
`UnsubscribeConfirmation`.

```javascript
if (message["Type"] === "UnsubscribeConfirmation") {
    // Unsubscribed in error? You can resubscribe by visiting the endpoint
    // provided as the message's SubscribeURL field.
    https.get(message["SubscribeURL"], function (res) {
        // You have re-subscribed your endpoint.
    });
}
```

[sns]: http://aws.amazon.com/sns/
[AWS SDK for JavaScript]: https://github.com/aws/aws-sdk-js
