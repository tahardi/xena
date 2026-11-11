import base64
import json
import os

import functions_framework
from googleapiclient import discovery


def over_budget(data):
    budget = json.loads(base64.b64decode(data))
    return budget["costAmount"] >= budget["budgetAmount"]


@functions_framework.cloud_event
def stop_billing(cloud_event):
    if not over_budget(cloud_event.data["message"]["data"]):
        return
    name = f"projects/{os.environ['SANDBOX_PROJECT']}"
    billing = discovery.build("cloudbilling", "v1", cache_discovery=False)
    info = billing.projects().getBillingInfo(name=name).execute()
    if info.get("billingEnabled"):
        billing.projects().updateBillingInfo(name=name, body={"billingAccountName": ""}).execute()
