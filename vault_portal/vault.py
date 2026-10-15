import copy
import requests

class VaultError(RuntimeError):
    def __init__(self, message, stale=False):
        super().__init__(message)
        self.stale = stale

class WriteOutcomeUnknown(VaultError):
    pass

# Clearly synthetic values. DemoVault is isolated from requests and never calls network APIs.
DEMO_DATA = {
    "Sandbox": {
        "TEST_gcp": {"gcp_id": "1000000", "gcp_name": "demo-project", "region": "asia-south1", "unrelated_demo_key": "preserved"},
        "TEST_token": {"token_gcp": "gcp_token=OLD_DEMO_TOKEN\\ngcp_region=asia-south1\\nnotes=keep-this-line"},
        "DEMO_service/config": {"endpoint": "https://demo.invalid", "retries": "3"},
    },
    "Pilot": {
        "TEST_gcp": {"gcp_id": "2000000", "gcp_name": "pilot-demo", "region": "asia-south1"},
        "TEST_token": {"token_gcp": "gcp_token=OLD_PILOT_DEMO_TOKEN\\ngcp_region=asia-south1"},
    },
    "Prod": {
        "TEST_gcp": {"gcp_id": "3000000", "gcp_name": "prod-demo-placeholder"},
        "TEST_token": {"token_gcp": "gcp_token=OLD_PROD_DEMO_PLACEHOLDER"},
    },
}

class DemoVault:
    def __init__(self, environment):
        self.environment = environment
        self.data = copy.deepcopy(DEMO_DATA[environment])
        self.versions = {path: 1 for path in self.data}
        self.write_count = 0

    def read_secret(self, path):
        if path not in self.data:
            return {}, None
        return copy.deepcopy(self.data[path]), self.versions[path]

    def write_secret(self, path, data, cas):
        current_version = self.versions.get(path, 0)
        if (cas or 0) != current_version:
            raise VaultError("Vault version changed. Create a fresh preview.", stale=True)
        self.data[path] = copy.deepcopy(data)
        self.versions[path] = current_version + 1
        self.write_count += 1

class RealVault:
    def __init__(self, address, token, timeout=8):
        self.address = address.rstrip("/")
        self._token = token
        self.timeout = timeout
        self.http = requests.Session()
        self.http.headers.update({"X-Vault-Token": token, "Content-Type": "application/json"})

    def _request(self, method, path, **kwargs):
        try:
            response = self.http.request(method, f"{self.address}/v1/{path}", timeout=self.timeout, **kwargs)
        except requests.Timeout:
            if method.upper() in ("POST", "PUT", "PATCH"):
                raise WriteOutcomeUnknown("Vault write outcome is unknown.")
            raise VaultError("Vault request timed out.")
        except requests.RequestException:
            if method.upper() in ("POST", "PUT", "PATCH"):
                raise WriteOutcomeUnknown("Vault write outcome is unknown.")
            raise VaultError("Could not connect to Vault.")
        if response.status_code == 404:
            return None
        if response.status_code == 403:
            raise VaultError("Vault denied the request. Check the server-side token policy.")
        if response.status_code == 400 and method.upper() == "POST":
            raise VaultError("Vault rejected the write (possibly a stale CAS version).", stale=True)
        if response.status_code >= 400:
            raise VaultError(f"Vault request failed with HTTP {response.status_code}. Sensitive response details are hidden.")
        try:
            return response.json()
        except ValueError:
            raise VaultError("Vault returned an unexpected response.")

    def test_connection(self):
        """Validate the token against Vault's token self-lookup endpoint."""
        result = self._request("GET", "auth/token/lookup-self")
        if not isinstance(result, dict) or not result.get("data"):
            raise VaultError("Vault did not confirm this token. Check the address and token policy.")
        return True

    def read_secret(self, path):
        safe_path = "/".join(part for part in path.split("/") if part)
        result = self._request("GET", f"secret/data/{safe_path}")
        if result is None:
            # A KV v2 read of a missing secret may return 404.
            return {}, None
        data = result.get("data", {})
        return data.get("data", {}), data.get("metadata", {}).get("version")

    def write_secret(self, path, data, cas):
        safe_path = "/".join(part for part in path.split("/") if part)
        self._request("POST", f"secret/data/{safe_path}", json={"options": {"cas": cas or 0}, "data": data})
