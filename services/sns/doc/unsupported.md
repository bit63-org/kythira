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

The pinned model has 42 operations. 21 are planned, all in task 4 (the
topic, subscription and publish API, with the gateway and authorization of
task 3 under it). The other 21 are SMS (11) and mobile push (10), which the
spec leaves out of scope: they stay here for good, with the same error.

| Operation | Planned | Reason | Error |
|---|---|---|---|
| `AddPermission` | task 4 | Not built yet (topic policies, evaluated from task 3). | `InvalidAction`, HTTP 400 |
| `CheckIfPhoneNumberIsOptedOut` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `ConfirmSubscription` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `CreatePlatformApplication` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `CreatePlatformEndpoint` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `CreateSMSSandboxPhoneNumber` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `CreateTopic` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `DeleteEndpoint` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `DeletePlatformApplication` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `DeleteSMSSandboxPhoneNumber` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `DeleteTopic` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `GetDataProtectionPolicy` | task 4 | Not built yet (stored, not enforced, Requirement 4.1 scope). | `InvalidAction`, HTTP 400 |
| `GetEndpointAttributes` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `GetPlatformApplicationAttributes` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `GetSMSAttributes` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `GetSMSSandboxAccountStatus` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `GetSubscriptionAttributes` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `GetTopicAttributes` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `ListEndpointsByPlatformApplication` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `ListOriginationNumbers` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `ListPhoneNumbersOptedOut` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `ListPlatformApplications` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `ListSMSSandboxPhoneNumbers` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `ListSubscriptions` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `ListSubscriptionsByTopic` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `ListTagsForResource` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `ListTopics` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `OptInPhoneNumber` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `Publish` | task 4 | Not built yet (publishing). | `InvalidAction`, HTTP 400 |
| `PublishBatch` | task 4 | Not built yet (publishing). | `InvalidAction`, HTTP 400 |
| `PutDataProtectionPolicy` | task 4 | Not built yet (stored, not enforced, Requirement 4.1 scope). | `InvalidAction`, HTTP 400 |
| `RemovePermission` | task 4 | Not built yet (topic policies, evaluated from task 3). | `InvalidAction`, HTTP 400 |
| `SetEndpointAttributes` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `SetPlatformApplicationAttributes` | none (out of scope) | Mobile push (platform applications and endpoints) has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `SetSMSAttributes` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
| `SetSubscriptionAttributes` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `SetTopicAttributes` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `Subscribe` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `TagResource` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `Unsubscribe` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `UntagResource` | task 4 | Not built yet (topic and subscription API). | `InvalidAction`, HTTP 400 |
| `VerifySMSSandboxPhoneNumber` | none (out of scope) | SMS has no Kythira counterpart. | `InvalidAction`, HTTP 400 |
