import json

from netguard.scanners.dependencies.parsers import pypi


def names(res):
    return {(p.name, p.version) for p in res.packages}


def test_requirements_pinned_only_and_name_normalisation():
    text = """\
# comment
Django==3.2.0
Flask_Cors[extras]==3.0.10 ; python_version >= "3.8"
requests>=2.0
numpy
-r other.txt
-e .
PyYAML==5.3 \\
    --hash=sha256:abc
"""
    res = pypi.parse_requirements(text, "requirements.txt")
    assert names(res) == {("django", "3.2.0"), ("flask-cors", "3.0.10"), ("pyyaml", "5.3")}
    assert "2 requirements are not pinned" in res.warnings[0]
    assert next(p for p in res.packages if p.name == "django").line == 2
    assert next(p for p in res.packages if p.name == "pyyaml").line == 8  # start of the logical line


def test_requirements_triple_equals():
    assert names(pypi.parse_requirements("foo===1.0.0+local\n", "r.txt")) == {("foo", "1.0.0+local")}


def test_pipfile_lock_default_and_develop():
    lock = {"default": {"Jinja2": {"version": "==2.11.2"}}, "develop": {"pytest": {"version": "==6.0.0"}}}
    res = pypi.parse_pipfile_lock(json.dumps(lock, indent=2), "Pipfile.lock")
    assert names(res) == {("jinja2", "2.11.2"), ("pytest", "6.0.0")}
    assert next(p for p in res.packages if p.name == "pytest").dev


POETRY = """\
[[package]]
name = "requests"
version = "2.25.0"

[package.dependencies]
urllib3 = ">=1.21"
idna = ">=2.5"

[[package]]
name = "urllib3"
version = "1.26.4"

[[package]]
name = "idna"
version = "2.10"

[[package]]
name = "Some_Tool"
version = "0.1.0"

[package.dependencies]
requests = "*"
"""


def test_poetry_lock_graph_paths_and_roots():
    res = pypi.parse_poetry_lock(POETRY, "poetry.lock")
    by = {p.name: p for p in res.packages}
    assert by["some-tool"].direct and by["some-tool"].path == ["some-tool"]
    assert by["urllib3"].path == ["some-tool", "requests", "urllib3"] and not by["urllib3"].direct
    assert by["idna"].path_text == "some-tool > requests > idna"


UV = """\
version = 1

[[package]]
name = "myapp"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "httpx" }]

[[package]]
name = "httpx"
version = "0.24.0"
dependencies = [{ name = "certifi" }]

[[package]]
name = "certifi"
version = "2022.12.7"
"""


def test_uv_lock_excludes_project_itself_and_tracks_chains():
    res = pypi.parse_uv_lock(UV, "uv.lock")
    by = {p.name: p for p in res.packages}
    assert set(by) == {"httpx", "certifi"}
    assert by["httpx"].direct and by["certifi"].path == ["httpx", "certifi"]


def test_pyproject_pins_only():
    toml = '[project]\nname = "x"\ndependencies = ["requests==2.31.0", "flask>=2"]\n'
    res = pypi.parse_pyproject(toml, "pyproject.toml")
    assert names(res) == {("requests", "2.31.0")} and "version ranges" in res.warnings[0]


def test_bad_toml_and_json_are_reported():
    assert "invalid TOML" in pypi.parse_poetry_lock("[[package", "poetry.lock").warnings[0]
    assert "invalid JSON" in pypi.parse_pipfile_lock("{", "Pipfile.lock").warnings[0]
