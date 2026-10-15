"""Collect dependency license texts, including nested bundled C-library notices."""
from pathlib import Path


def collect(metadata, project):
    sections = [
        'THIRD-PARTY NOTICES\n\n'
        'This distribution includes Sequoia OpenPGP (LGPL-2.0-or-later), OpenSSL\n'
        '(Apache-2.0), and other dependencies listed below. Full corresponding\n'
        'sources, license files, and instructions for rebuilding/relinking are\n'
        'provided in the matching source release archive. Alternative licenses\n'
        'remain available where the upstream project offers them.\n'
    ]
    for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
        directory = Path(package['manifest_path']).parent
        if directory == project:
            continue
        files = sorted(
            p for p in directory.rglob('*')
            if p.is_file() and p.name.upper().startswith(
                ('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'COPYRIGHT', 'AUTHORS')
            )
        )
        supplement = project / 'licenses' / f"{package['name']}-{package['version']}.txt"
        if supplement.is_file():
            files.append(supplement)
        if not files:
            raise SystemExit(f"Missing license notice: {package['name']} {package['version']}")
        sections.append(f"\n{'=' * 72}\n{package['name']} {package['version']}\nLicense expression: {package['license']}\n")
        for file in files:
            label = file.name if file == supplement else file.relative_to(directory)
            sections.append(f'\n--- {label} ---\n{file.read_text(errors="replace")}\n')
    return ''.join(sections)


if __name__ == '__main__':
    import json
    import subprocess
    project = Path(__file__).resolve().parents[1]
    metadata = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--format-version', '1'], cwd=project
    ))
    print(collect(metadata, project))
