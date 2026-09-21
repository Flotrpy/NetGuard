import json

from netguard.scanners.dependencies.parsers import npm

LOCK_V3 = {
    "name": "app",
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "^29.0.0"}},
        "node_modules/express": {"version": "4.18.2", "dependencies": {"qs": "6.11.0", "cookie": "0.5.0"}},
        "node_modules/qs": {"version": "6.11.0", "dependencies": {"side-channel": "^1.0.4"}},
        "node_modules/side-channel": {"version": "1.0.4"},
        "node_modules/cookie": {"version": "0.5.0"},
        "node_modules/jest": {"version": "29.7.0", "dev": True},
        "node_modules/express/node_modules/cookie": {"version": "0.4.0"},
    },
}


def by_name(result, name, version=None):
    return [p for p in result.packages if p.name == name and (version is None or p.version == version)]


def test_lock_v3_versions_dev_flag_and_direct():
    res = npm.parse_package_lock(json.dumps(LOCK_V3, indent=2), "package-lock.json")
    assert {p.name for p in res.packages} == {"express", "qs", "side-channel", "cookie", "jest"}
    express = by_name(res, "express")[0]
    assert express.version == "4.18.2" and express.direct and not express.dev
    assert by_name(res, "jest")[0].dev and by_name(res, "jest")[0].direct
    assert not by_name(res, "qs")[0].direct


def test_lock_v3_dependency_chains_use_real_graph():
    res = npm.parse_package_lock(json.dumps(LOCK_V3), "package-lock.json")
    assert by_name(res, "side-channel")[0].path == ["express", "qs", "side-channel"]
    assert by_name(res, "qs")[0].path_text == "express > qs"


def test_nested_node_modules_resolution_picks_the_right_copy():
    res = npm.parse_package_lock(json.dumps(LOCK_V3), "package-lock.json")
    cookies = {p.version: p for p in by_name(res, "cookie")}
    assert set(cookies) == {"0.5.0", "0.4.0"}
    # express requires cookie 0.5.0 -> resolves to the nested copy first (0.4.0), per Node semantics.
    assert cookies["0.4.0"].path == ["express", "cookie"]


def test_line_numbers_point_into_the_lockfile():
    text = json.dumps(LOCK_V3, indent=2)
    res = npm.parse_package_lock(text, "package-lock.json")
    qs = by_name(res, "qs")[0]
    assert '"node_modules/qs"' in text.splitlines()[qs.line - 1]


def test_lock_v1_nested_tree():
    v1 = {"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0", "dev": True}}}}}
    res = npm.parse_package_lock(json.dumps(v1), "package-lock.json")
    b = by_name(res, "b")[0]
    assert b.path == ["a", "b"] and not b.direct and b.dev
    assert by_name(res, "a")[0].direct


def test_invalid_and_empty_locks_warn_instead_of_crashing():
    assert "invalid JSON" in npm.parse_package_lock("{nope", "p.json").warnings[0]
    assert npm.parse_package_lock("{}", "p.json").warnings


def test_scoped_packages():
    lock = {"packages": {"": {"dependencies": {"@babel/core": "^7"}},
                         "node_modules/@babel/core": {"version": "7.20.0"}}}
    res = npm.parse_package_lock(json.dumps(lock), "package-lock.json")
    assert res.packages[0].name == "@babel/core"


YARN = '''# yarn lockfile v1


"@babel/core@^7.0.0", "@babel/core@^7.20.0":
  version "7.20.5"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.20.5.tgz"

lodash@^4.17.15:
  version "4.17.15"
  dependencies:
    other "1.0.0"
'''


def test_yarn_lock_v1():
    res = npm.parse_yarn_lock(YARN, "yarn.lock")
    assert {(p.name, p.version) for p in res.packages} == {("@babel/core", "7.20.5"), ("lodash", "4.17.15")}
    assert by_name(res, "lodash")[0].line == 9


def test_yarn_berry_is_reported_unsupported():
    res = npm.parse_yarn_lock("__metadata:\n  version: 6\n", "yarn.lock")
    assert res.packages == [] and "Berry" in res.warnings[0]


def test_package_json_only_checks_pinned_versions_and_says_so():
    pj = json.dumps({"dependencies": {"left-pad": "1.3.0", "express": "^4.0.0"},
                     "devDependencies": {"mocha": "10.2.0"}})
    res = npm.parse_package_json(pj, "package.json")
    assert {(p.name, p.dev) for p in res.packages} == {("left-pad", False), ("mocha", True)}
    assert "add a lockfile" in res.warnings[0]
