# SNS operations not implemented

`.kiro/specs/sns-compatible-notifications/` Requirement 2.1: every operation
in the pinned model (`../model/service-2.json`, botocore 1.43.126) is either
implemented, and then listed in `../implemented-operations.txt`, or listed
here with its reason and the exact error it returns.
`tools/check_coverage.py` (the ctest `sns_model_coverage`) fails when an
operation is in neither list, so a model upgrade that adds one fails until it
is placed.

The front end (`include/kythira/sns/sns_front_end.hpp`, task 3) answers an
operation listed here like an action the model does not have: the query
protocol's `InvalidAction` error (`<Type>Sender</Type>`, HTTP status 400) in
SNS's `ErrorResponse` XML, with the message `Could not find operation
<Action> for version 2010-03-31`. The request is authenticated first, so an
unsigned caller gets SigV4's error instead. Task 12's recorded SNS
responses pin the exact message.

The pinned model has 42 operations. 12 are implemented (the topic,
attribute, tag, permission and data protection operations of task 4).
9 more are planned in task 4: the subscription operations and publishing.
The other 21 are SMS (11) and mobile push (10), which the spec leaves out
of scope: they stay here for good, with the same error.

`PutDataProtectionPolicy` and `GetDataProtectionPolicy` are implemented as
storage: the policy is validated as a JSON object, kept and returned, but
Kythira does not enforce it (no message is audited, masked or denied).

| Operation | Planned | Reason | Error |
|---|---|---|---|
| `CheckIfPhoneNumberIsOptedOut` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `ConfirmSubscription` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `CreatePlatformApplication` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `CreatePlatformEndpoint` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `CreateSMSSandboxPhoneNumber` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `DeleteEndpoint` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `DeletePlatformApplication` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `DeleteSMSSandboxPhoneNumber` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `GetEndpointAttributes` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `GetPlatformApplicationAttributes` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `GetSMSAttributes` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `GetSMSSandboxAccountStatus` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `GetSubscriptionAttributes` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `ListEndpointsByPlatformApplication` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `ListOriginationNumbers` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `ListPhoneNumbersOptedOut` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `ListPlatformApplications` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `ListSMSSandboxPhoneNumbers` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `ListSubscriptions` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `ListSubscriptionsByTopic` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `OptInPhoneNumber` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `Publish` | task 4 | Not built yet (publishing). | `InvalidAction`, HTTP 400 |
| `PublishBatch` | task 4 | Not built yet (publishing). | `InvalidAction`, HTTP 400 |
| `SetEndpointAttributes` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `SetPlatformApplicationAttributes` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `SetSMSAttributes` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `SetSubscriptionAttributes` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `Subscribe` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `Unsubscribe` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `VerifySMSSandboxPhoneNumber` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
