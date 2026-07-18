import email.parser
import importlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]


def load_pyproject():
    with (ROOT / "pyproject.toml").open("rb") as pyproject_file:
        return tomllib.load(pyproject_file)


def test_pyproject_metadata_and_python_requirement():
    project = load_pyproject()["project"]
    assert project["name"] == "password-locker"
    assert project["version"] == "2.0.0"
    assert project["requires-python"] == ">=3.10"
    assert project["readme"] == "README.md"
    assert project["authors"] == [{"name": "David Mevorah"}]


def test_runtime_dependencies_are_bounded_and_minimal():
    dependencies = [
        Requirement(value) for value in load_pyproject()["project"]["dependencies"]
    ]
    assert {dependency.name.casefold() for dependency in dependencies} == {
        "pycryptodome",
        "pyperclip",
    }
    assert all(str(dependency.specifier) for dependency in dependencies)


def test_development_dependency_group_is_bounded_and_compatible():
    development = load_pyproject()["project"]["optional-dependencies"]["dev"]
    requirements = [Requirement(value) for value in development]
    by_name = {requirement.name.casefold(): requirement for requirement in requirements}
    assert set(by_name) == {"pytest", "setuptools", "tomli"}

    pytest_requirement = by_name["pytest"]
    assert Version("8.3") in pytest_requirement.specifier
    assert Version("10") not in pytest_requirement.specifier
    assert pytest_requirement.marker is None

    build_requirement = Requirement(load_pyproject()["build-system"]["requires"][0])
    setuptools_requirement = by_name["setuptools"]
    assert setuptools_requirement.specifier == build_requirement.specifier
    assert setuptools_requirement.marker is None

    tomli_requirement = by_name["tomli"]
    assert Version("2.0.1") in tomli_requirement.specifier
    assert Version("3") not in tomli_requirement.specifier
    assert str(tomli_requirement.marker) == 'python_version < "3.11"'


def test_pep639_license_metadata_is_declared():
    pyproject = load_pyproject()
    project = pyproject["project"]
    build_requirement = Requirement(pyproject["build-system"]["requires"][0])
    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    assert build_requirement.name == "setuptools"
    assert "77.0.3" in str(build_requirement.specifier)


def test_cli_and_gui_entry_points_target_secure_interfaces():
    project = load_pyproject()["project"]
    assert project["scripts"] == {
        "password-locker": "password_locker.cli:main"
    }
    assert project["gui-scripts"] == {
        "password-locker-gui": "password_locker.gui:main"
    }


def test_package_discovery_includes_only_application_package():
    discovery = load_pyproject()["tool"]["setuptools"]["packages"]["find"]
    assert discovery["where"] == ["."]
    assert discovery["include"] == ["password_locker"]
    assert discovery["exclude"] == ["tests", "tests.*"]
    assert discovery["namespaces"] is False


def test_icon_is_declared_as_package_data():
    package_data = load_pyproject()["tool"]["setuptools"]["package-data"]
    assert package_data == {"password_locker": ["assets/*.ico"]}


def test_importing_gui_entry_point_module_does_not_create_window(monkeypatch):
    import tkinter

    def fail_if_called(*args, **kwargs):
        raise AssertionError("GUI import must not create a Tk root")

    monkeypatch.setattr(tkinter, "Tk", fail_if_called)
    sys.modules.pop("password_locker.gui", None)
    module = importlib.import_module("password_locker.gui")
    assert callable(module.main)


def test_wheel_contains_pep639_license_metadata(tmp_path):
    source = tmp_path / "source"
    package = source / "password_locker"
    wheel_directory = tmp_path / "wheel"
    source.mkdir()
    wheel_directory.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy2(ROOT / name, source / name)
    shutil.copytree(
        ROOT / "password_locker",
        package,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            str(source),
            "--wheel-dir",
            str(wheel_directory),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    wheels = list(wheel_directory.glob("*.whl"))
    assert len(wheels) == 1

    with zipfile.ZipFile(wheels[0]) as wheel:
        names = wheel.namelist()
        metadata_name = next(
            name for name in names if name.endswith(".dist-info/METADATA")
        )
        license_names = [
            name for name in names if name.endswith(".dist-info/licenses/LICENSE")
        ]
        metadata = email.parser.BytesParser().parsebytes(wheel.read(metadata_name))

    assert len(license_names) == 1
    assert metadata["License-Expression"] == "MIT"
    assert metadata.get_all("License-File") == ["LICENSE"]
    assert names.count("password_locker/assets/password-locker.ico") == 1
    assert "favicon.ico" not in names
    forbidden = (
        "tests/",
        "users.db",
        "vault.db",
        ".env",
        ".exe",
        ".log",
        ".idea/",
        "__pycache__",
        ".pyc",
    )
    assert not any(any(item in name for item in forbidden) for name in names)
