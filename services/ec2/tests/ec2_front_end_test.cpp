// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The EC2 front end (`.kiro/specs/ec2-compatible-api/` task 3,
// Requirements 3.2-3.5): real SigV4 through the static-key authorizer,
// EC2's framing and protocol errors, unsupported operations, every
// resource a request is authorized on with its condition keys, tagging on
// create and iam:PassRole, DryRun, the encoded authorization message,
// admission, and the handler safety nets.

#define BOOST_TEST_MODULE ec2_front_end_test
#include <boost/test/unit_test.hpp>

#include <kythira/ec2/ec2_front_end.hpp>
#include <kythira/ec2/ec2_throttle.hpp>

#include <raft/static_key_authorizer.hpp>

#include <algorithm>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ec2 = kythira::ec2;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace e = kythira::aws_ec2;

namespace {

constexpr std::string_view k_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
constexpr std::string_view k_account = "111122223333";
constexpr std::string_view k_form = "application/x-www-form-urlencoded; charset=utf-8";
constexpr std::string_view k_version = "&Version=2016-11-15";
const auto k_now = sv4::detail::parse_amz_date("20261127T120000Z").value();

auto post(std::string body, std::string_view content_type = k_form) -> ec2::front_end_request {
    ec2::front_end_request r;
    r._method = "POST";
    r._path = "/";
    r._body = std::move(body);
    r._source_ip = "192.0.2.10";
    r._headers = {{"Host", "ec2.us-east-1.amazonaws.com"},
                  {"Content-Type", std::string(content_type)},
                  {"X-Amz-Date", "20261127T120000Z"}};
    return r;
}

// Signs `r` as `akid` (header form), as an SDK does.
auto sign(ec2::front_end_request r, std::string_view akid) -> ec2::front_end_request {
    sv4::service_rules rules;
    rules.service = "ec2";
    rules.protocol = sv4::error_protocol::query;
    const sv4::credential_scope scope{"20261127", "us-east-1", "ec2"};
    const bool has_type = !ec2::front_end_detail::header_value(r, "Content-Type").empty();
    r._headers.emplace_back(
        "Authorization", "AWS4-HMAC-SHA256 Credential=" + std::string(akid) + "/" + scope.text() +
                             ", SignedHeaders=" + (has_type ? "content-type;" : "") +
                             "host;x-amz-date, Signature=" + std::string(64, '0'));
    const auto parsed =
        sv4::parse(sv4::request{r._method, r._path, r._query, r._headers, r._body}, rules, k_now);
    BOOST_REQUIRE_MESSAGE(parsed.has_value(), parsed.error().message);
    const auto sig = sv4::compute_signature(*parsed, sv4::derive_signing_key(k_secret, scope));
    r._headers.back().second.replace(r._headers.back().second.size() - 64, 64, sig);
    return r;
}

auto element(const std::string& xml, std::string_view tag) -> std::string {
    const auto open = "<" + std::string(tag) + ">";
    const auto close = "</" + std::string(tag) + ">";
    const auto a = xml.find(open);
    const auto b = xml.find(close, a);
    if (a == std::string::npos || b == std::string::npos) {
        return {};
    }
    return xml.substr(a + open.size(), b - a - open.size());
}

auto code_of(const ec2::front_end_response& r) -> std::string {
    return element(r._body, "Code");
}

/// Records whether `execute` ran, so DryRun can be shown to change nothing.
struct calls {
    int executed = 0;
};

/// A handler whose plan is `plan(params)` and whose answer echoes the
/// caller.
auto handler(calls& c, std::function<ec2::authz_plan(const e::params&)> plan = {})
    -> ec2::operation_handler {
    return {
        [plan](ec2::call_context&, const e::params& p) -> e::result<ec2::authz_plan> {
            if (const auto bad = p.get("Bad")) {
                return e::make_error(e::codes::invalid_parameter_value, std::string(*bad));
            }
            return plan ? plan(p) : ec2::authz_plan{};
        },
        [&c](ec2::call_context& ctx, const e::params&) -> e::result<std::string> {
            ++c.executed;
            return "<who>" + ctx._principal.arn + "</who><readOnly>" +
                   (ctx._read_only ? "true" : "false") + "</readOnly>";
        },
    };
}

/// RunInstances's plan, as task 13's handler will build it.
auto run_plan(const e::params& p) -> ec2::authz_plan {
    ec2::authz_plan plan;
    plan.on("instance", "*")._keys = {
        {"ec2:InstanceType", {std::string(p.get("InstanceType").value_or(""))}}};
    auto& image = plan.on("image", std::string(p.get("ImageId").value_or("")));
    image._resource_tags = {{"team", "base"}};
    plan.on("subnet", "subnet-0000000000000a001");
    if (const auto tags = e::tag_specifications(p); tags && !tags->empty()) {
        ec2::tag_pairs pairs;
        for (const auto& t : tags->front().tags) {
            pairs.emplace_back(t.key, t.value.value_or(""));
        }
        plan.tag_on_create("RunInstances", "instance", "*", pairs);
    }
    if (const auto role = p.get("IamInstanceProfile.Arn")) {
        plan._pass_roles.emplace_back(*role);
    }
    return plan;
}

struct static_fixture {
    az::static_key_authorizer auth{{{"AKIDADMIN", std::string(k_secret), std::string(k_account),
                                     "admin", az::static_role::admin},
                                    {"AKIDWRITER", std::string(k_secret), std::string(k_account),
                                     "writer", az::static_role::read_write},
                                    {"AKIDREADER", std::string(k_secret), std::string(k_account),
                                     "reader", az::static_role::read_only}},
                                   "aws",
                                   [] { return k_now; }};
    ec2::front_end<az::static_key_authorizer> fe{ec2::front_end_config{}, auth};
    calls c;

    static_fixture() {
        auth.register_service(ec2::ec2_static_roles());
        fe.on("DescribeInstances", handler(c));
        fe.on("RunInstances", handler(c, run_plan));
        fe.on("CreateVpc", handler(c, [](const e::params&) {
                  ec2::authz_plan p;
                  p.on("vpc", "*");
                  return p;
              }));
    }

    auto call(std::string body, std::string_view akid) -> ec2::front_end_response {
        return fe.handle(sign(post(std::move(body)), akid));
    }
};

/// Authenticates everyone as one principal and records each authorization
/// request; `deny` names actions to refuse.
struct recording_authorizer {
    az::principal_context who;
    std::vector<az::authz_request> seen;
    std::vector<std::string> deny;
    bool explicit_deny = false;
    std::optional<std::string> encoded;

    recording_authorizer() {
        who.account = std::string(k_account);
        who.arn = "arn:aws:iam::" + std::string(k_account) + ":user/alice";
        who.access_key_id = "AKIDALICE";
    }

    auto authenticate(const sv4::request&, const sv4::service_rules&) -> az::authn_result {
        return who;
    }

    auto authorize(const az::principal_context&, const az::authz_request& r) -> az::authz_decision {
        seen.push_back(r);
        az::authz_decision d;
        d.allowed = std::find(deny.begin(), deny.end(), r.action) == deny.end();
        d.explicit_deny = !d.allowed && explicit_deny;
        if (!d.allowed && r.want_encoded_message) {
            d.encoded_message = encoded;
        }
        return d;
    }
};

static_assert(az::aws_request_authorizer<recording_authorizer>);

struct recording_fixture {
    recording_authorizer auth;
    ec2::front_end<recording_authorizer> fe{ec2::front_end_config{}, auth};
    calls c;

    recording_fixture() {
        fe.on("DescribeInstances", handler(c));
        fe.on("RunInstances", handler(c, run_plan));
        // A resource-level action whose handler names no resource.
        fe.on("AttachVolume", handler(c));
        fe.on("CreateVolume", handler(c, [](const e::params&) {
                  ec2::authz_plan p;
                  auto& v = p.on("volume", "*");
                  v._keys = {{"ec2:Encrypted", {"true"}}, {"ec2:VolumeType", {"gp3"}}};
                  return p;
              }));
        fe.on("StopInstances",
              {[](ec2::call_context&, const e::params&) -> e::result<ec2::authz_plan> {
                   throw std::runtime_error("boom");
               },
               [](ec2::call_context&, const e::params&) -> e::result<std::string> {
                   return std::string();
               }});
    }

    auto call(std::string body) -> ec2::front_end_response {
        return fe.handle(post(std::move(body)));
    }

    [[nodiscard]] auto seen(std::string_view action) const -> std::vector<az::authz_request> {
        std::vector<az::authz_request> out;
        for (const auto& r : auth.seen) {
            if (r.action == action) {
                out.push_back(r);
            }
        }
        return out;
    }

    [[nodiscard]] static auto key(const az::authz_request& r, std::string_view name)
        -> std::vector<std::string> {
        for (const auto& [k, v] : r.keys) {
            if (k == name) {
                return v;
            }
        }
        return {"<absent>"};
    }
};

const std::string k_run =
    "Action=RunInstances" + std::string(k_version) +
    "&ImageId=ami-0000000000000a001&InstanceType=t3.micro&MinCount=1&MaxCount=1";

}  // namespace

BOOST_AUTO_TEST_SUITE(sigv4_and_framing)

BOOST_FIXTURE_TEST_CASE(a_signed_describe_reaches_its_handler, static_fixture) {
    const auto r = call("Action=DescribeInstances" + std::string(k_version), "AKIDREADER");
    BOOST_TEST(r._status == 200U);
    BOOST_TEST(r._body.find("<DescribeInstancesResponse "
                            "xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\"><requestId>") !=
               std::string::npos);
    BOOST_TEST(element(r._body, "who") == "arn:aws:iam::111122223333:user/reader");
    BOOST_TEST(element(r._body, "readOnly") == "true");
    BOOST_TEST(element(r._body, "requestId").size() == 36U);
    const auto header = std::find_if(r._headers.begin(), r._headers.end(),
                                     [](const auto& h) { return h.first == "x-amzn-RequestId"; });
    BOOST_REQUIRE(header != r._headers.end());
    BOOST_TEST(header->second == element(r._body, "requestId"));
}

BOOST_FIXTURE_TEST_CASE(a_signed_get_reaches_its_handler, static_fixture) {
    auto req = post("");
    req._method = "GET";
    req._headers.erase(req._headers.begin() + 1);  // no Content-Type
    req._query = "Action=DescribeInstances" + std::string(k_version);
    const auto r = fe.handle(sign(req, "AKIDREADER"));
    BOOST_TEST(r._status == 200U);
}

BOOST_FIXTURE_TEST_CASE(an_unknown_key_is_auth_failure, static_fixture) {
    const auto r = call("Action=DescribeInstances" + std::string(k_version), "AKIDNOBODY");
    BOOST_TEST(r._status == 401U);
    BOOST_TEST(code_of(r) == "AuthFailure");
    BOOST_TEST(element(r._body, "Message") ==
               "AWS was not able to validate the provided access credentials");
    BOOST_TEST(r._body.find("<Response><Errors><Error>") != std::string::npos);
    BOOST_TEST(element(r._body, "RequestID").size() == 36U);
    BOOST_TEST(c.executed == 0);
}

BOOST_FIXTURE_TEST_CASE(an_unsigned_request_learns_nothing, static_fixture) {
    // Even an action that does not exist gets SigV4's answer first.
    const auto r = fe.handle(post("Action=NoSuchThing"));
    BOOST_TEST(r._status >= 400U);
    BOOST_TEST(code_of(r) != "InvalidAction");
    BOOST_TEST(!code_of(r).empty());
}

BOOST_FIXTURE_TEST_CASE(a_tampered_body_does_not_match, static_fixture) {
    auto req = sign(post("Action=DescribeInstances" + std::string(k_version)), "AKIDREADER");
    req._body += "&InstanceId.1=i-1";
    const auto r = fe.handle(req);
    BOOST_TEST(code_of(r) == "SignatureDoesNotMatch");
    BOOST_TEST(r._status == 403U);
}

BOOST_FIXTURE_TEST_CASE(framing_errors_are_malformed_query_string, recording_fixture) {
    auto put = post("Action=DescribeInstances" + std::string(k_version));
    put._method = "PUT";
    BOOST_TEST(code_of(fe.handle(put)) == "MalformedQueryString");
    BOOST_TEST(code_of(fe.handle(post("Action=DescribeInstances", "application/json"))) ==
               "MalformedQueryString");
    BOOST_TEST(code_of(call(std::string(2U * 1024U * 1024U, 'a'))) == "MalformedQueryString");
    BOOST_TEST(code_of(call("Action=DescribeInstances&Action=RunInstances")) ==
               "MalformedQueryString");
    BOOST_TEST(c.executed == 0);
}

BOOST_FIXTURE_TEST_CASE(protocol_errors_come_from_the_codec, recording_fixture) {
    BOOST_TEST(code_of(call("Version=2016-11-15")) == "MissingAction");
    BOOST_TEST(code_of(call("Action=DescribeInstances")) == "MissingParameter");
    BOOST_TEST(code_of(call("Action=DescribeInstances&Version=2014-01-01")) == "NoSuchVersion");
    const auto bad = call("Action=LaunchRocket" + std::string(k_version));
    BOOST_TEST(code_of(bad) == "InvalidAction");
    BOOST_TEST(bad._status == 400U);
}

BOOST_FIXTURE_TEST_CASE(an_unimplemented_operation_is_unsupported, recording_fixture) {
    const auto r = call("Action=CreateSecurityGroup" + std::string(k_version) +
                        "&GroupName=web&GroupDescription=web");
    BOOST_TEST(r._status == 400U);
    BOOST_TEST(code_of(r) == "UnsupportedOperation");
    BOOST_TEST(auth.seen.empty());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(authorization)

BOOST_FIXTURE_TEST_CASE(static_roles_split_reads_runs_and_networks, static_fixture) {
    BOOST_TEST(call("Action=DescribeInstances" + std::string(k_version), "AKIDREADER")._status ==
               200U);
    const auto denied = call(k_run, "AKIDREADER");
    BOOST_TEST(denied._status == 403U);
    BOOST_TEST(code_of(denied) == "UnauthorizedOperation");
    // The static-key authorizer seals no message.
    BOOST_TEST(element(denied._body, "Message").find("Encoded authorization failure message") ==
               std::string::npos);
    BOOST_TEST(call(k_run, "AKIDWRITER")._status == 200U);
    const auto vpc = "Action=CreateVpc" + std::string(k_version) + "&CidrBlock=10.0.0.0%2F16";
    BOOST_TEST(code_of(call(vpc, "AKIDWRITER")) == "UnauthorizedOperation");
    BOOST_TEST(call(vpc, "AKIDADMIN")._status == 200U);
}

BOOST_FIXTURE_TEST_CASE(a_resourceless_action_is_authorized_on_star, recording_fixture) {
    BOOST_TEST(call("Action=DescribeInstances" + std::string(k_version))._status == 200U);
    BOOST_REQUIRE_EQUAL(auth.seen.size(), 1U);
    BOOST_TEST(auth.seen[0].action == "ec2:DescribeInstances");
    BOOST_TEST(auth.seen[0].resource == "*");
    BOOST_TEST(key(auth.seen[0], "ec2:Region") == std::vector<std::string>{"us-east-1"});
    BOOST_TEST(auth.seen[0].want_encoded_message);
    BOOST_TEST(auth.seen[0].source_ip == "192.0.2.10");
}

BOOST_FIXTURE_TEST_CASE(run_instances_is_checked_on_every_resource, recording_fixture) {
    const auto r = call(k_run +
                        "&TagSpecification.1.ResourceType=instance"
                        "&TagSpecification.1.Tag.1.Key=Name&TagSpecification.1.Tag.1.Value=web"
                        "&IamInstanceProfile.Arn=arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fweb");
    BOOST_TEST(r._status == 200U);
    const auto run = seen("ec2:RunInstances");
    BOOST_REQUIRE_EQUAL(run.size(), 3U);
    BOOST_TEST(run[0].resource == "arn:aws:ec2:us-east-1:111122223333:instance/*");
    BOOST_TEST(key(run[0], "ec2:InstanceType") == std::vector<std::string>{"t3.micro"});
    // Image ARNs carry no account, as on EC2; the image's tags reach both
    // tag key families.
    BOOST_TEST(run[1].resource == "arn:aws:ec2:us-east-1::image/ami-0000000000000a001");
    BOOST_TEST(key(run[1], "ec2:ResourceTag/team") == std::vector<std::string>{"base"});
    BOOST_TEST(run[1].resource_tags.size() == 1U);
    BOOST_TEST(run[2].resource ==
               "arn:aws:ec2:us-east-1:111122223333:subnet/subnet-0000000000000a001");

    const auto tag = seen("ec2:CreateTags");
    BOOST_REQUIRE_EQUAL(tag.size(), 1U);
    BOOST_TEST(key(tag[0], "ec2:CreateAction") == std::vector<std::string>{"RunInstances"});
    BOOST_TEST(key(tag[0], "aws:TagKeys") == std::vector<std::string>{"Name"});
    BOOST_REQUIRE(tag[0].request_tags.has_value());
    BOOST_TEST(tag[0].request_tags->front().second == "web");

    const auto pass = seen("iam:PassRole");
    BOOST_REQUIRE_EQUAL(pass.size(), 1U);
    BOOST_TEST(pass[0].resource == "arn:aws:iam::111122223333:role/web");
    BOOST_TEST(key(pass[0], "iam:PassedToService") ==
               std::vector<std::string>{"ec2.amazonaws.com"});
}

BOOST_FIXTURE_TEST_CASE(untagged_creates_skip_create_tags, recording_fixture) {
    BOOST_TEST(call(k_run)._status == 200U);
    BOOST_TEST(seen("ec2:CreateTags").empty());
    BOOST_TEST(seen("iam:PassRole").empty());
}

BOOST_FIXTURE_TEST_CASE(condition_keys_reach_the_authorizer, recording_fixture) {
    BOOST_TEST(
        call("Action=CreateVolume" + std::string(k_version) + "&AvailabilityZone=us-east-1a&Size=8")
            ._status == 200U);
    const auto v = seen("ec2:CreateVolume");
    BOOST_REQUIRE_EQUAL(v.size(), 1U);
    BOOST_TEST(v[0].resource == "arn:aws:ec2:us-east-1:111122223333:volume/*");
    BOOST_TEST(key(v[0], "ec2:Encrypted") == std::vector<std::string>{"true"});
    BOOST_TEST(key(v[0], "ec2:VolumeType") == std::vector<std::string>{"gp3"});
}

BOOST_FIXTURE_TEST_CASE(a_denial_carries_the_encoded_message, recording_fixture) {
    auth.deny = {"ec2:RunInstances"};
    auth.encoded = "sealed-for-sts";
    const auto r = call(k_run);
    BOOST_TEST(r._status == 403U);
    BOOST_TEST(code_of(r) == "UnauthorizedOperation");
    const auto m = element(r._body, "Message");
    BOOST_TEST(
        m.starts_with("You are not authorized to perform this operation. User: "
                      "arn:aws:iam::111122223333:user/alice is not authorized to perform: "
                      "ec2:RunInstances on resource: "
                      "arn:aws:ec2:us-east-1:111122223333:instance/*"));
    BOOST_TEST(m.ends_with(". Encoded authorization failure message: sealed-for-sts"));
    BOOST_TEST(c.executed == 0);
}

BOOST_FIXTURE_TEST_CASE(an_explicit_deny_says_so, recording_fixture) {
    auth.deny = {"iam:PassRole"};
    auth.explicit_deny = true;
    const auto r = call(k_run + "&IamInstanceProfile.Arn=arn%3Aaws%3Aiam%3A%3A1%3Arole%2Fx");
    BOOST_TEST(code_of(r) == "UnauthorizedOperation");
    BOOST_TEST(element(r._body, "Message")
                   .find("iam:PassRole on resource: arn:aws:iam::1:role/x "
                         "with an explicit deny") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(a_handler_that_names_no_resource_is_refused, recording_fixture) {
    // AttachVolume acts on an instance and a volume; a plan that names
    // neither must not fall back to `*`.
    const auto r = call("Action=AttachVolume" + std::string(k_version) +
                        "&Device=%2Fdev%2Fsdf&InstanceId=i-1&VolumeId=vol-1");
    BOOST_TEST(r._status == 500U);
    BOOST_TEST(code_of(r) == "InternalError");
    BOOST_TEST(auth.seen.empty());
    BOOST_TEST(c.executed == 0);
}

BOOST_FIXTURE_TEST_CASE(an_empty_plan_is_never_unauthorized_success, recording_fixture) {
    // The reference gives this operation no action; a handler that names
    // none either gets InternalError, not an unchecked answer.
    fe.on("GetCapacityManagerSupportabilityScores", handler(c));
    const auto r = call("Action=GetCapacityManagerSupportabilityScores" + std::string(k_version));
    BOOST_TEST(code_of(r) == "InternalError");
    BOOST_TEST(c.executed == 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(dry_run_and_dispatch)

BOOST_FIXTURE_TEST_CASE(a_permitted_dry_run_changes_nothing, recording_fixture) {
    const auto r = call(k_run + "&DryRun=true");
    BOOST_TEST(r._status == 412U);
    BOOST_TEST(code_of(r) == "DryRunOperation");
    BOOST_TEST(element(r._body, "Message") ==
               "Request would have succeeded, but DryRun flag is set.");
    BOOST_TEST(!seen("ec2:RunInstances").empty());
    BOOST_TEST(c.executed == 0);
}

BOOST_FIXTURE_TEST_CASE(a_refused_dry_run_is_unauthorized, recording_fixture) {
    auth.deny = {"ec2:RunInstances"};
    const auto r = call(k_run + "&DryRun=true");
    BOOST_TEST(r._status == 403U);
    BOOST_TEST(code_of(r) == "UnauthorizedOperation");
    BOOST_TEST(c.executed == 0);
}

BOOST_FIXTURE_TEST_CASE(an_invalid_dry_run_fails_validation_first, recording_fixture) {
    // Validation errors win over DryRun, as on EC2: a dry run that would
    // fail says why.
    BOOST_TEST(code_of(call(k_run + "&DryRun=maybe")) == "InvalidParameterValue");
    const auto r = call(k_run + "&DryRun=true&Bad=nope");
    BOOST_TEST(code_of(r) == "InvalidParameterValue");
    BOOST_TEST(element(r._body, "Message") == "nope");
    BOOST_TEST(auth.seen.empty());
}

BOOST_FIXTURE_TEST_CASE(dry_run_false_runs_the_operation, recording_fixture) {
    const auto r = call(k_run + "&DryRun=false");
    BOOST_TEST(r._status == 200U);
    BOOST_TEST(element(r._body, "readOnly") == "false");
    BOOST_TEST(c.executed == 1);
}

BOOST_FIXTURE_TEST_CASE(an_exception_is_internal_error, recording_fixture) {
    const auto r = call("Action=StopInstances" + std::string(k_version) + "&InstanceId.1=i-1");
    BOOST_TEST(r._status == 500U);
    BOOST_TEST(code_of(r) == "InternalError");
}

BOOST_FIXTURE_TEST_CASE(admission_runs_after_authentication, recording_fixture) {
    ec2::ec2_throttle throttle;
    fe.set_admission([&](std::string_view op, const az::principal_context& who,
                         const e::params& p) { return throttle.admit(who.account, op, p); });
    // RunInstances has a bucket of five calls.
    for (int i = 0; i < 5; ++i) {
        BOOST_TEST(call(k_run)._status == 200U);
    }
    const auto r = call(k_run);
    BOOST_TEST(r._status == 503U);
    BOOST_TEST(code_of(r) == "RequestLimitExceeded");
    BOOST_TEST(c.executed == 5);
    // Other buckets are untouched.
    BOOST_TEST(call("Action=DescribeInstances" + std::string(k_version))._status == 200U);
}

BOOST_AUTO_TEST_CASE(registration_is_checked) {
    recording_authorizer auth;
    ec2::front_end<recording_authorizer> fe{ec2::front_end_config{}, auth};
    calls c;
    BOOST_CHECK_THROW(fe.on("LaunchRocket", handler(c)), std::invalid_argument);
    BOOST_CHECK_THROW(fe.on("RunInstances", ec2::operation_handler{}), std::invalid_argument);
    fe.on("RunInstances", handler(c));
    BOOST_CHECK_THROW(fe.on("RunInstances", handler(c)), std::invalid_argument);
    BOOST_TEST(fe.handles("RunInstances"));
    BOOST_TEST(!fe.handles("StopInstances"));
}

BOOST_AUTO_TEST_SUITE_END()
