import io
from app import create_app
from vault_portal.vault import DemoVault

def make_client():
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "VAULT_MODE": "demo"})
    # One stable in-memory demo vault per environment, so applies persist within test.
    vaults = {}
    def factory(env):
        vaults.setdefault(env, DemoVault(env))
        return vaults[env]
    app.extensions["vault_client_factory"] = factory
    return app.test_client(), app, vaults

def csrf(client):
    response = client.get("/")
    # Session cookie is established by request; fetch token through test request context.
    with client.session_transaction() as sess:
        return sess["_csrf"]

def upload(client, files, environment="Sandbox"):
    token = csrf(client)
    data = {"environment": environment, "csrf_token": token, "files": [(io.BytesIO(content.encode()), name) for name, content in files]}
    return client.post("/preview", data=data, content_type="multipart/form-data", follow_redirects=True)

def test_demo_upload_preview_and_apply_one_only():
    client, app, vaults = make_client()
    response = upload(client, [
        ("one.txt", "SECRET: TEST_gcp\nSET gcp_name = changed-demo"),
        ("two.txt", "SECRET: TEST_token\nSET_NESTED token_gcp : gcp_token = NEW_DEMO_TOKEN"),
    ])
    assert b"one.txt" in response.data and b"two.txt" in response.data
    with client.session_transaction() as sess:
        pid = sess["preview_id"]
    preview = app.extensions["vault_previews"][pid]
    first, second = preview["entries"]
    token = csrf(client)
    response = client.post(f"/apply/{first['id']}", data={"csrf_token": token}, follow_redirects=True)
    assert b"applied" in response.data.lower()
    assert first["status"] == "applied"
    assert second["status"] == "pending"

def test_apply_all_pending():
    client, app, _vaults = make_client()
    upload(client, [
        ("one.txt", "SECRET: TEST_gcp\nSET gcp_name = changed-demo"),
        ("two.txt", "SECRET: TEST_token\nSET_NESTED token_gcp : gcp_token = NEW_DEMO_TOKEN"),
    ])
    with client.session_transaction() as sess:
        preview = app.extensions["vault_previews"][sess["preview_id"]]
    token = csrf(client)
    client.post("/apply-all", data={"csrf_token": token}, follow_redirects=True)
    assert all(e["status"] == "applied" for e in preview["entries"])

def test_duplicate_application_prevented():
    client, app, _vaults = make_client()
    upload(client, [("one.txt", "SECRET: TEST_gcp\nSET gcp_name = changed-demo")])
    with client.session_transaction() as sess:
        entry = app.extensions["vault_previews"][sess["preview_id"]]["entries"][0]
    token = csrf(client)
    client.post(f"/apply/{entry['id']}", data={"csrf_token": token})
    assert entry["status"] == "applied"
    client.post(f"/apply/{entry['id']}", data={"csrf_token": token})
    assert entry["status"] == "applied"

def test_csrf_rejected():
    client, _app, _vaults = make_client()
    response = client.post("/clear", data={"csrf_token": "wrong"})
    assert response.status_code == 400

def test_demo_mode_never_calls_network(monkeypatch):
    import requests
    def fail(*args, **kwargs):
        raise AssertionError("Demo mode must not perform network requests")
    monkeypatch.setattr(requests, "request", fail)
    monkeypatch.setattr(requests.Session, "request", fail)
    client, _app, _vaults = make_client()
    response = upload(client, [("one.txt", "SECRET: TEST_gcp\nSET gcp_name = changed-demo")])
    assert b"one.txt" in response.data

def test_duplicate_secret_paths_rejected():
    client, _app, _vaults = make_client()
    response = upload(client, [
        ("one.txt", "SECRET: TEST_gcp\nSET a = 1"),
        ("two.txt", "SECRET: TEST_gcp\nSET b = 2"),
    ])
    assert b"Multiple files target the same secret path" in response.data

def test_demo_connections_page_never_connects_to_vault():
    client, _app, _vaults = make_client()
    response = client.get('/connections')
    assert response.status_code == 200
    assert b'Demo mode is network-isolated' in response.data


def test_key_reference_resolves_from_another_secret_and_is_checked_on_apply():
    client, app, vaults = make_client()
    response = upload(client, [
        ('reference.txt', 'SECRET: DEMO_service/config\nSET copied_id = Key: <TEST_gcp.gcp_id>')
    ])
    assert b'1000000' in response.data
    with client.session_transaction() as sess:
        preview = app.extensions['vault_previews'][sess['preview_id']]
    entry = preview['entries'][0]
    assert entry['after']['copied_id'] == '1000000'
    source = vaults['Sandbox']
    source.write_secret('TEST_gcp', {**source.data['TEST_gcp'], 'gcp_id': 'changed-source'}, cas=source.versions['TEST_gcp'])
    token = csrf(client)
    client.post(f"/apply/{entry['id']}", data={'csrf_token': token})
    assert entry['status'] == 'stale'


def test_connection_form_uses_code_allowlist_and_saves_only_after_validation(monkeypatch):
    from vault_portal.vault import RealVault
    app = create_app({'TESTING': True, 'SECRET_KEY': 'test-secret', 'VAULT_MODE': 'real'})
    client = app.test_client()
    client.get('/connections')
    token = csrf(client)
    monkeypatch.setattr('app.ALLOWED_VAULT_HOSTS', {'vault.example.com'})
    monkeypatch.setattr(RealVault, 'test_connection', lambda self: True)
    response = client.post('/connections/add', data={
        'csrf_token': token,
        'environment': 'Sandbox',
        'address': 'https://vault.example.com',
        'token': 'synthetic-test-token',
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'CONNECTED IN MEMORY' in response.data
    assert app.extensions['vault_connections']['Sandbox']['address'] == 'https://vault.example.com'
