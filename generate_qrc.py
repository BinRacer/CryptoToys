# -*- coding: utf-8 -*
import os
import sys
from pathlib import Path

def generate_qrc_file():
    root_dir = Path(__file__).parent
    ui_dir = root_dir / "ui"
    qrc_path = root_dir / "ui.qrc"

    if not ui_dir.exists() or not ui_dir.is_dir():
        print(f"Error: ui directory does not exist {ui_dir}")
        sys.exit(1)

    file_paths = []
    for root, _, files in os.walk(ui_dir):
        for file in files:
            file_path = Path(root) / file
            rel_path = file_path.relative_to(ui_dir)
            file_paths.append(rel_path.as_posix())

    qrc_content = ['<RCC>']
    qrc_content.append('    <qresource compress="0" prefix="/">')

    for rel_path in file_paths:
        alias = f"{rel_path}"
        qrc_content.append(f'        <file alias="{alias}">ui/{rel_path}</file>')

    qrc_content.append('    </qresource>')
    qrc_content.append('</RCC>')

    with open(qrc_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(qrc_content))

    print(f"[+] ui.qrc has been successfully updated with {len(file_paths)} resource files")

if __name__ == "__main__":
    generate_qrc_file()
