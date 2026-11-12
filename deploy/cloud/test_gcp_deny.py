import json
import os
import unittest

POLICY_PATH = os.path.join(os.path.dirname(__file__), "gcp-deny.json")
DEV = "principal://iam.googleapis.com/projects/-/serviceAccounts/xena-dev@SANDBOX_PROJECT.iam.gserviceaccount.com"


class TestGCPDeny(unittest.TestCase):
    def test_rule(self):
        # given
        with open(POLICY_PATH) as f:
            policy = json.load(f)

        # when
        rules = policy["rules"]

        # then
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["denyRule"]["deniedPrincipals"], [DEV])
        self.assertNotIn("exceptionPrincipals", rules[0]["denyRule"])

    def test_denied(self):
        with open(POLICY_PATH) as f:
            denied = set(json.load(f)["rules"][0]["denyRule"]["deniedPermissions"])

        cases = [
            "iam.googleapis.com/serviceAccountKeys.create",
            "iam.googleapis.com/serviceAccounts.create",
            "iam.googleapis.com/serviceAccounts.setIamPolicy",
            "iam.googleapis.com/serviceAccounts.actAs",
            "iam.googleapis.com/serviceAccounts.getAccessToken",
            "iam.googleapis.com/serviceAccounts.getOpenIdToken",
            "iam.googleapis.com/serviceAccounts.signBlob",
            "iam.googleapis.com/serviceAccounts.signJwt",
            "iam.googleapis.com/serviceAccounts.implicitDelegation",
            "iam.googleapis.com/workloadIdentityPools.create",
            "iam.googleapis.com/workloadIdentityPoolProviders.create",
            "storage.googleapis.com/hmacKeys.create",
            "cloudresourcemanager.googleapis.com/projects.setIamPolicy",
        ]
        for permission in cases:
            with self.subTest(permission=permission):
                # given
                want = True

                # when
                got = permission in denied

                # then
                self.assertEqual(got, want)


if __name__ == "__main__":
    unittest.main()
