def _create(client, name="My Web App"):
    r = client.post("/api/projects", json={"name": name, "description": "demo"})
    assert r.status_code == 201, r.text
    return r.json()


def test_create_list_get_update_delete(client):
    client.register()
    p = _create(client)
    assert p["role"] == "owner" and p["open_findings"]["critical"] == 0
    assert [x["id"] for x in client.get("/api/projects").json()] == [p["id"]]
    assert client.get(f"/api/projects/{p['id']}").json()["name"] == "My Web App"
    r = client.patch(f"/api/projects/{p['id']}", json={"name": "Renamed"})
    assert r.json()["name"] == "Renamed"
    assert client.delete(f"/api/projects/{p['id']}").status_code == 204
    assert client.get(f"/api/projects/{p['id']}").status_code == 404


def test_validation(client):
    client.register()
    assert client.post("/api/projects", json={"name": ""}).status_code == 422
    assert client.post("/api/projects", json={"name": "x" * 201}).status_code == 422


def test_projects_are_isolated_between_users(client, make_client):
    client.register("owner@example.com")
    p = _create(client)
    other = make_client("other@example.com")
    assert other.get("/api/projects").json() == []
    # 404 (not 403) so project existence is not leaked; mutation is also denied.
    assert other.get(f"/api/projects/{p['id']}").status_code == 404
    assert other.patch(f"/api/projects/{p['id']}", json={"name": "hax"}).status_code == 404
    assert other.delete(f"/api/projects/{p['id']}").status_code == 404


def test_admin_can_access_all_projects(client, make_client):
    client.register("admin@example.com")  # first user => admin
    other = make_client("member@example.com")
    p = _create(other, "Member project")
    assert client.get(f"/api/projects/{p['id']}").status_code == 200


def test_membership_roles_are_enforced(client, make_client):
    client.register("admin@example.com")
    owner = make_client("owner@example.com")
    viewer = make_client("viewer@example.com")
    editor = make_client("editor@example.com")
    p = _create(owner)

    assert owner.post(f"/api/projects/{p['id']}/members", json={"email": "viewer@example.com", "role": "viewer"}).status_code == 201
    assert owner.post(f"/api/projects/{p['id']}/members", json={"email": "editor@example.com", "role": "editor"}).status_code == 201

    assert viewer.get(f"/api/projects/{p['id']}").json()["role"] == "viewer"
    assert viewer.patch(f"/api/projects/{p['id']}", json={"name": "x"}).status_code == 403
    assert editor.patch(f"/api/projects/{p['id']}", json={"name": "Edited"}).status_code == 200
    # Editors can't manage members or delete.
    assert editor.post(f"/api/projects/{p['id']}/members", json={"email": "viewer@example.com", "role": "editor"}).status_code == 403
    assert editor.delete(f"/api/projects/{p['id']}").status_code == 403

    emails = {m["email"] for m in owner.get(f"/api/projects/{p['id']}/members").json()}
    assert {"owner@example.com", "viewer@example.com", "editor@example.com"} <= emails

    vid = next(m["user_id"] for m in owner.get(f"/api/projects/{p['id']}/members").json() if m["email"] == "viewer@example.com")
    assert owner.delete(f"/api/projects/{p['id']}/members/{vid}").status_code == 204
    assert viewer.get(f"/api/projects/{p['id']}").status_code == 404


def test_cannot_grant_owner_role_or_add_unknown_user(client):
    client.register()
    p = _create(client)
    assert client.post(f"/api/projects/{p['id']}/members", json={"email": "x@y.io", "role": "owner"}).status_code == 422
    assert client.post(f"/api/projects/{p['id']}/members", json={"email": "ghost@example.com", "role": "viewer"}).status_code == 404
