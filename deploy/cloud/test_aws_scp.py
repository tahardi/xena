import fnmatch
import json
import os
import unittest

SCP_PATH = os.path.join(os.path.dirname(__file__), "aws-scp.json")
ADMIN = "arn:aws:iam::111122223333:role/OrganizationAccountAccessRole"
DEV = "arn:aws:iam::111122223333:role/xena-dev"
GRANTER = "arn:aws:iam::111122223333:user/xena-granter"
MAX_SCP_SIZE = 5120


def load():
    with open(SCP_PATH) as f:
        return f.read()


def as_list(value):
    return value if isinstance(value, list) else [value]


def condition_applies(statement, principal):
    condition = statement.get("Condition", {})
    if not condition:
        return True

    patterns = as_list(condition.get("ArnNotLike", {}).get("aws:PrincipalArn", []))
    if set(condition) != {"ArnNotLike"} or not patterns:
        return False

    return not any(fnmatch.fnmatchcase(principal, p) for p in patterns)


def denied(policy, action, principal):
    for statement in policy["Statement"]:
        if statement["Effect"] != "Deny" or "Action" not in statement:
            continue

        actions = as_list(statement["Action"])
        if not any(fnmatch.fnmatchcase(action.lower(), a.lower()) for a in actions):
            continue

        if condition_applies(statement, principal):
            return True

    return False


class TestAWSSCP(unittest.TestCase):
    def test_size(self):
        self.assertLessEqual(len(load()), MAX_SCP_SIZE)

    def test_denied(self):
        policy = json.loads(load())
        cases = [
            ("iam:CreateRole", DEV, True),
            ("iam:UpdateAssumeRolePolicy", DEV, True),
            ("iam:PutRolePolicy", DEV, True),
            ("iam:AttachRolePolicy", DEV, True),
            ("iam:DeleteRolePermissionsBoundary", DEV, True),
            ("iam:CreatePolicyVersion", DEV, True),
            ("iam:SetDefaultPolicyVersion", DEV, True),
            ("iam:PutUserPolicy", DEV, True),
            ("iam:AttachUserPolicy", DEV, True),
            ("iam:AddUserToGroup", DEV, True),
            ("iam:PutGroupPolicy", DEV, True),
            ("iam:AttachGroupPolicy", DEV, True),
            ("iam:UpdateLoginProfile", DEV, True),
            ("iam:CreateServiceSpecificCredential", DEV, True),
            ("iam:UploadSSHPublicKey", DEV, True),
            ("iam:UploadSigningCertificate", DEV, True),
            ("iam:CreateOpenIDConnectProvider", DEV, True),
            ("iam:CreateSAMLProvider", DEV, True),
            ("iam:CreateInstanceProfile", DEV, True),
            ("iam:AddRoleToInstanceProfile", DEV, True),
            ("iam:PassRole", DEV, True),
            ("rolesanywhere:CreateTrustAnchor", DEV, True),
            ("iam:CreateUser", DEV, True),
            ("iam:CreateAccessKey", DEV, True),
            ("iam:CreateRole", ADMIN, False),
            ("iam:PassRole", ADMIN, False),
            ("iam:CreateServiceLinkedRole", DEV, False),
            ("iam:CreateAccessKey", GRANTER, False),
            ("iam:DeleteAccessKey", GRANTER, False),
            ("sts:AssumeRole", GRANTER, False),
        ]
        for action, principal, want in cases:
            with self.subTest(action=action, principal=principal):
                # given
                name = principal.rsplit("/", 1)[1]

                # when
                got = denied(policy, action, principal)

                # then
                self.assertEqual(got, want, f"{action} for {name}")


if __name__ == "__main__":
    unittest.main()
