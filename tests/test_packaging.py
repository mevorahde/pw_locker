import importlib
import sys
import tomllib
from pathlib import Path

from packaging.requirements import Requirement


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


def test_development_dependency_group_contains_only_pytest():
    development = load_pyproject()["project"]["optional-dependencies"]["dev"]
    requirements = [Requirement(value) for value in development]
    assert [requirement.name.casefold() for requirement in requirements] == ["pytest"]
    assert str(requirements[0].specifier)


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


def test_importing_gui_entry_point_module_does_not_create_window(monkeypatch):
    import tkinter

    def fail_if_called(*args, **kwargs):
        raise AssertionError("GUI import must not create a Tk root")

    monkeypatch.setattr(tkinter, "Tk", fail_if_called)
    sys.modules.pop("password_locker.gui", None)
    module = importlib.import_module("password_locker.gui")
    assert callable(module.main)
