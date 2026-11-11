import base64
import json
import os
import sys
import types
import unittest
from unittest import mock

functions_framework = types.ModuleType("functions_framework")
functions_framework.cloud_event = lambda fn: fn
googleapiclient = types.ModuleType("googleapiclient")
discovery = types.ModuleType("googleapiclient.discovery")
discovery.build = mock.MagicMock()
googleapiclient.discovery = discovery
sys.modules["functions_framework"] = functions_framework
sys.modules["googleapiclient"] = googleapiclient
sys.modules["googleapiclient.discovery"] = discovery
os.environ["SANDBOX_PROJECT"] = "example-sandbox"

import main  # noqa: E402


def encode(cost, budget):
    return base64.b64encode(json.dumps({"costAmount": cost, "budgetAmount": budget}).encode())


def event(cost, budget):
    return types.SimpleNamespace(data={"message": {"data": encode(cost, budget)}})


class StopBillingTest(unittest.TestCase):
    def setUp(self):
        discovery.build.reset_mock(return_value=True, side_effect=True)
        self.billing = mock.MagicMock()
        discovery.build.return_value = self.billing
        self.projects = self.billing.projects.return_value

    def test_over_budget(self):
        cases = [(21, 20, True), (20, 20, True), (5, 20, False)]
        for cost, budget, want in cases:
            with self.subTest(cost=cost, budget=budget):
                self.assertEqual(main.over_budget(encode(cost, budget)), want)

    def test_stop_billing_disables(self):
        self.projects.getBillingInfo.return_value.execute.return_value = {"billingEnabled": True}

        main.stop_billing(event(21, 20))

        self.projects.getBillingInfo.assert_called_once_with(name="projects/example-sandbox")
        self.projects.updateBillingInfo.assert_called_once_with(
            name="projects/example-sandbox",
            body={"billingAccountName": ""},
        )

    def test_stop_billing_already_disabled(self):
        self.projects.getBillingInfo.return_value.execute.return_value = {"billingEnabled": False}

        main.stop_billing(event(21, 20))

        self.projects.updateBillingInfo.assert_not_called()

    def test_stop_billing_under_budget(self):
        main.stop_billing(event(5, 20))

        discovery.build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
