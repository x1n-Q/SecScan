"""Auto-detect project type from folder contents."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import Iterator, List, Sequence


@dataclass
class ProjectInfo:
    """Detected project metadata."""
    path: str
    types: List[str]
    has_dockerfile: bool = False
    has_iac: bool = False
    website_url: str = ""
    # --- Enhanced metadata ---
    languages: List[str] = field(default_factory=list)
    dependency_files: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    iac_types: List[str] = field(default_factory=list)


# Mapping of marker files / dirs to project type labels
_MARKERS: dict[str, str] = {
    "package.json": "node",
    "yarn.lock": "node",
    "pnpm-lock.yaml": "node",
    "package-lock.json": "node",
    "requirements.txt": "python",
    "setup.py": "python",
    "pyproject.toml": "python",
    "Pipfile": "python",
    "Pipfile.lock": "python",
    "poetry.lock": "python",
    "go.mod": "go",
    "go.sum": "go",
    "Cargo.toml": "rust",
    "Cargo.lock": "rust",
    "pom.xml": "java-maven",
    "build.gradle": "java-gradle",
    "build.gradle.kts": "java-gradle",
    "Gemfile": "ruby",
    "Gemfile.lock": "ruby",
    "composer.json": "php",
    "composer.lock": "php",
    "*.csproj": "dotnet",
    "*.sln": "dotnet",
}

# Files that represent dependency manifests (for the dependency_files field)
_DEPENDENCY_FILES: dict[str, str] = {
    "package.json": "node",
    "package-lock.json": "node",
    "yarn.lock": "node",
    "pnpm-lock.yaml": "node",
    "requirements.txt": "python",
    "Pipfile": "python",
    "Pipfile.lock": "python",
    "poetry.lock": "python",
    "pyproject.toml": "python",
    "go.mod": "go",
    "go.sum": "go",
    "Cargo.toml": "rust",
    "Cargo.lock": "rust",
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "java",
    "Gemfile": "ruby",
    "Gemfile.lock": "ruby",
    "composer.json": "php",
    "composer.lock": "php",
}

# Language label mapping
_TYPE_TO_LANGUAGE: dict[str, str] = {
    "node": "javascript",
    "python": "python",
    "go": "go",
    "rust": "rust",
    "java-maven": "java",
    "java-gradle": "java",
    "ruby": "ruby",
    "php": "php",
    "dotnet": "csharp",
}

_DOCKERFILE_PATTERNS = (
    "Dockerfile",
    "dockerfile",
    "Containerfile",
    "Dockerfile.*",
    "dockerfile.*",
    "Containerfile.*",
)
_IAC_MARKERS: dict[str, str] = {
    "main.tf": "terraform",
    "*.tf": "terraform",
    "*.tfvars": "terraform",
    "template.yaml": "cloudformation",
    "serverless.yml": "serverless",
    "ansible.cfg": "ansible",
    "playbook.yml": "ansible",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    "compose.yml": "docker-compose",
    "compose.yaml": "docker-compose",
    "render.yaml": "render",
    "vercel.json": "vercel",
    "Chart.yaml": "kubernetes",
    "values.yaml": "kubernetes",
    "*.k8s.yaml": "kubernetes",
    "*.k8s.yml": "kubernetes",
    "*deployment*.yaml": "kubernetes",
    "*deployment*.yml": "kubernetes",
    "*service*.yaml": "kubernetes",
    "*service*.yml": "kubernetes",
    "*ingress*.yaml": "kubernetes",
    "*ingress*.yml": "kubernetes",
    "*daemonset*.yaml": "kubernetes",
    "*daemonset*.yml": "kubernetes",
    "*statefulset*.yaml": "kubernetes",
    "*statefulset*.yml": "kubernetes",
}

# Framework detection heuristics (file -> framework name)
_FRAMEWORK_MARKERS: dict[str, str] = {
    "vite.config.js": "Vite",
    "vite.config.ts": "Vite",
    "vite.config.mjs": "Vite",
    "next.config.js": "Next.js",
    "next.config.mjs": "Next.js",
    "next.config.ts": "Next.js",
    "nuxt.config.js": "Nuxt.js",
    "nuxt.config.ts": "Nuxt.js",
    "angular.json": "Angular",
    "vue.config.js": "Vue.js",
    "svelte.config.js": "SvelteKit",
    "gatsby-config.js": "Gatsby",
    "remix.config.js": "Remix",
    "manage.py": "Django",
    "app.py": "Flask/FastAPI",
    "Procfile": "Heroku",
}

_SOURCE_LANGUAGE_PATTERNS: dict[str, str] = {
    "*.py": "python",
    "*.js": "javascript",
    "*.jsx": "javascript",
    "*.mjs": "javascript",
    "*.cjs": "javascript",
    "*.ts": "typescript",
    "*.tsx": "typescript",
    "*.vue": "vue",
    "*.svelte": "svelte",
    "*.php": "php",
    "*.go": "go",
    "*.rs": "rust",
    "*.java": "java",
    "*.cs": "csharp",
    "*.rb": "ruby",
    "*.kt": "kotlin",
    "*.swift": "swift",
    "*.scala": "scala",
    "*.html": "html",
    "*.css": "css",
    "*.scss": "scss",
    "*.sass": "sass",
    "*.less": "less",
    "*.sql": "sql",
    "*.sh": "shell",
    "*.bash": "shell",
    "*.zsh": "shell",
    "*.ps1": "powershell",
    "*.yaml": "yaml",
    "*.yml": "yaml",
    "*.tf": "terraform",
    "*.tfvars": "terraform",
    "Dockerfile": "docker",
    "dockerfile": "docker",
    "Containerfile": "docker",
    "Dockerfile.*": "docker",
    "dockerfile.*": "docker",
    "Containerfile.*": "docker",
}

_LANGUAGE_TO_TYPE: dict[str, str] = {
    "python": "python",
    "javascript": "node",
    "typescript": "node",
    "php": "php",
    "go": "go",
    "rust": "rust",
    "java": "java-maven",
    "csharp": "dotnet",
    "ruby": "ruby",
}

_K8S_MARKERS = (
    "Chart.yaml",
    "values.yaml",
    "*.k8s.yaml",
    "*.k8s.yml",
    "*deployment*.yaml",
    "*deployment*.yml",
    "*service*.yaml",
    "*service*.yml",
    "*ingress*.yaml",
    "*ingress*.yml",
    "*daemonset*.yaml",
    "*daemonset*.yml",
    "*statefulset*.yaml",
    "*statefulset*.yml",
)

_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".turbo",
    ".cache",
    "coverage",
    "target",
    "out",
    "bin",
    "obj",
    "secscan-results",
    "secscan-results-test",
    ".secscan-history",
}
_MAX_SCAN_DEPTH = 6


def _iter_project_tree(path: str, max_depth: int = _MAX_SCAN_DEPTH) -> Iterator[tuple[str, list[str]]]:
    """Yield project directories and filenames, skipping bulky/generated folders."""
    root_depth = path.rstrip("\\/").count(os.sep)
    for dirpath, dirnames, filenames in os.walk(path):
        depth = dirpath.rstrip("\\/").count(os.sep) - root_depth
        dirnames[:] = [d for d in dirnames if d not in _IGNORE_DIRS]
        if depth > max_depth:
            dirnames[:] = []
            continue
        yield dirpath, filenames


def _rel_path(base_path: str, full_path: str) -> str:
    rel = os.path.relpath(full_path, base_path)
    return "." if rel == "." else rel.replace(os.sep, "/")


def find_project_files(
    path: str,
    *,
    names: Sequence[str] = (),
    patterns: Sequence[str] = (),
    max_depth: int = _MAX_SCAN_DEPTH,
) -> list[str]:
    """Return matching files under a project, relative to *path*."""
    if not os.path.isdir(path):
        return []

    exact = set(names)
    found: list[str] = []
    seen: set[str] = set()

    for dirpath, filenames in _iter_project_tree(path, max_depth=max_depth):
        for filename in filenames:
            if filename in exact or any(fnmatch.fnmatch(filename, pattern) for pattern in patterns):
                rel = _rel_path(path, os.path.join(dirpath, filename))
                if rel not in seen:
                    seen.add(rel)
                    found.append(rel)

    found.sort(key=str.lower)
    return found


def find_kubernetes_files(path: str, max_depth: int = _MAX_SCAN_DEPTH) -> list[str]:
    """Return Kubernetes-leaning manifest files under a project."""
    exact = [marker for marker in _K8S_MARKERS if "*" not in marker]
    patterns = [marker for marker in _K8S_MARKERS if "*" in marker]
    return find_project_files(path, names=exact, patterns=patterns, max_depth=max_depth)


def find_python_projects(path: str, max_depth: int = _MAX_SCAN_DEPTH) -> list[str]:
    """Return directories that look like Python projects."""
    manifests = find_project_files(
        path,
        names=("requirements.txt", "setup.py", "pyproject.toml", "Pipfile"),
        max_depth=max_depth,
    )
    project_dirs = {
        path if "/" not in rel_path else os.path.join(path, os.path.dirname(rel_path))
        for rel_path in manifests
    }
    return sorted(
        project_dirs,
        key=lambda p: (
            0 if os.path.abspath(p) == os.path.abspath(path) else 1,
            p.lower(),
        ),
    )


def find_npm_projects(path: str, max_depth: int = _MAX_SCAN_DEPTH) -> list[str]:
    """Return directories that contain a package.json manifest."""
    manifests = find_project_files(path, names=("package.json",), max_depth=max_depth)
    project_dirs = {
        path if rel_path == "package.json" else os.path.join(path, os.path.dirname(rel_path))
        for rel_path in manifests
    }
    return sorted(
        project_dirs,
        key=lambda p: (
            0 if os.path.abspath(p) == os.path.abspath(path) else 1,
            p.lower(),
        ),
    )


def detect_project(path: str, website_url: str = "") -> ProjectInfo:
    """Scan *path* for marker files and return a ProjectInfo describing the project."""
    if not os.path.isdir(path):
        return ProjectInfo(path=path, types=["unknown"])

    found_types: set[str] = set()
    found_languages: set[str] = set()
    found_dep_files: list[str] = []
    found_frameworks: set[str] = set()
    found_iac_types: set[str] = set()
    has_dockerfile = False
    has_iac = False

    marker_names = [marker for marker in _MARKERS if not marker.startswith("*")]
    marker_patterns = [marker for marker in _MARKERS if marker.startswith("*")]
    dep_names = list(_DEPENDENCY_FILES)
    framework_names = list(_FRAMEWORK_MARKERS)

    matched_markers = find_project_files(path, names=marker_names, patterns=marker_patterns)
    matched_dep_files = find_project_files(path, names=dep_names)
    matched_frameworks = find_project_files(path, names=framework_names)
    matched_dockerfiles = find_project_files(path, patterns=_DOCKERFILE_PATTERNS)
    matched_iac_files = find_project_files(path, names=[m for m in _IAC_MARKERS if not m.startswith("*")], patterns=[m for m in _IAC_MARKERS if m.startswith("*")])
    matched_source_files = find_project_files(path, patterns=list(_SOURCE_LANGUAGE_PATTERNS))

    # Check marker files found anywhere in the project tree.
    for rel_path in matched_markers:
        filename = os.path.basename(rel_path)
        for marker, ptype in _MARKERS.items():
            if filename == marker or (marker.startswith("*") and fnmatch.fnmatch(filename, marker)):
                found_types.add(ptype)

    # Collect dependency files with relative paths for monorepos.
    found_dep_files.extend(matched_dep_files)

    # Map types to languages
    for ptype in found_types:
        lang = _TYPE_TO_LANGUAGE.get(ptype)
        if lang:
            found_languages.add(lang)

    # Language detection from source files helps repos without lockfiles/manifests.
    for rel_path in matched_source_files:
        filename = os.path.basename(rel_path)
        for pattern, language in _SOURCE_LANGUAGE_PATTERNS.items():
            if fnmatch.fnmatch(filename, pattern):
                found_languages.add(language)

    for language in found_languages:
        ptype = _LANGUAGE_TO_TYPE.get(language)
        if ptype:
            found_types.add(ptype)

    # Framework detection
    for rel_path in matched_frameworks:
        fw = _FRAMEWORK_MARKERS.get(os.path.basename(rel_path))
        if fw:
            found_frameworks.add(fw)

    # Dockerfile check
    has_dockerfile = bool(matched_dockerfiles)

    # IaC check
    if matched_iac_files:
        has_iac = True
        for rel_path in matched_iac_files:
            filename = os.path.basename(rel_path)
            for marker, iac_type in _IAC_MARKERS.items():
                if filename == marker or (marker.startswith("*") and fnmatch.fnmatch(filename, marker)):
                    found_iac_types.add(iac_type)

    if not found_types:
        found_types.add("unknown")

    return ProjectInfo(
        path=path,
        types=sorted(found_types),
        has_dockerfile=has_dockerfile,
        has_iac=has_iac,
        website_url=website_url,
        languages=sorted(found_languages),
        dependency_files=sorted(found_dep_files),
        frameworks=sorted(found_frameworks),
        iac_types=sorted(found_iac_types),
    )
