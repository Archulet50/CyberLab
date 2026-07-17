#!/usr/bin/env python3
"""
Generate missing README.md files for numbered CyberLab Python projects.

Existing README files are skipped and never overwritten.
"""

from pathlib import Path
import re
import sys


def project_name_from_folder(folder_name: str) -> str:
    """Convert '01_System_Check' into 'System Check'."""
    name_without_number = re.sub(r"^\d+_", "", folder_name)
    return name_without_number.replace("_", " ")


def main() -> int:
    repository_root = Path(__file__).resolve().parent.parent
    python_directory = repository_root / "Python"
    template_path = (
        repository_root
        / "docs"
        / "templates"
        / "PROJECT_README_TEMPLATE.md"
    )

    if not python_directory.is_dir():
        print(f"[ERROR] Project directory not found: {python_directory}")
        return 1

    if not template_path.is_file():
        print(f"[ERROR] Template not found: {template_path}")
        return 1

    template = template_path.read_text(encoding="utf-8")

    project_directories = sorted(
        directory
        for directory in python_directory.iterdir()
        if directory.is_dir() and re.match(r"^\d+_", directory.name)
    )

    created = 0
    skipped = 0

    for project_directory in project_directories:
        readme_path = project_directory / "README.md"

        if readme_path.exists():
            print(f"[SKIP]   {readme_path.relative_to(repository_root)}")
            skipped += 1
            continue

        project_name = project_name_from_folder(project_directory.name)

        readme_content = (
            template
            .replace("{{PROJECT_NAME}}", project_name)
            .replace("{{FOLDER_NAME}}", project_directory.name)
        )

        readme_path.write_text(readme_content, encoding="utf-8")
        print(f"[CREATE] {readme_path.relative_to(repository_root)}")
        created += 1

    print()
    print("README generation complete.")
    print(f"Created: {created}")
    print(f"Skipped: {skipped}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
