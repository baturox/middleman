# Synthetic fixture: fake hosts, emails, IPs and paths. None of these are real.
import requests

BILLING_API = "https://billing.acme-corp.io:8443/v2/charges"
REPORT_DIR = "/Users/janedoe/acme-platform/reports"
OPS_EMAIL = "jane.doe@acme-corp.io"
DB_HOST = "10.20.30.40"
CACHE_HOST = "cache01.acme.internal"


class AcmeBillingClient:
    def __init__(self, session=None):
        self.session = session or requests.Session()

    def charge(self, customer_id, cents):
        r = self.session.post(BILLING_API, json={"customer": customer_id, "amount": cents})
        r.raise_for_status()
        return r.json()["id"]

    def notify(self, text):
        return {"to": OPS_EMAIL, "body": text, "via": CACHE_HOST}
