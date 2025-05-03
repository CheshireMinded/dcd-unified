# TO MANUALLY CLEAN BAIT FILES: find /home/student/dcd-unified/data/ -type f -name 'bait_*' -delete
#!/usr/bin/env python3

import os
import random
import shutil
from faker import Faker
from datetime import datetime

fake = Faker()

# Directories per honeypot
HONEYPOT_BAIT_DIRS = {
    "cowrie": "/home/student/dcd-unified/data/cowrie/bait",
    "dionaea": "/home/student/dcd-unified/data/dionaea/bait",
    "elasticpot": "/home/student/dcd-unified/data/elasticpot/bait",
    "heralding": "/home/student/dcd-unified/data/heralding/bait",
    "tanner": "/home/student/dcd-unified/data/tanner/bait"
}

FILE_EXTENSIONS = ['.conf', '.log', '.sql', '.txt', '.ini', '.json']

FAKE_PASSWORDS = [
    'admin:admin123',
    'root:toor',
    'user:Pa$$w0rd!',
    'pi:raspberry',
    'test:test1234'
]

FAKE_API_KEYS = [
    f"APIKEY-{fake.sha1()[:24]}",
    f"ghp_{fake.sha1()[:36]}",
    f"aws:{fake.sha256()[:20]}"
]

FAKE_BANNERS = [
    "220 (vsFTPd 3.0.3)\n",
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\n",
    "MySQL 5.7.33-0ubuntu0.18.04.1-log\n",
    "PostgreSQL 12.7 on x86_64-pc-linux-gnu\n",
    "Microsoft Windows RPC Endpoint Mapper"
]

def clear_directory(path):
    if os.path.exists(path):
        for entry in os.listdir(path):
            full_path = os.path.join(path, entry)
            try:
                if os.path.isfile(full_path) or os.path.islink(full_path):
                    os.unlink(full_path)
                elif os.path.isdir(full_path):
                    shutil.rmtree(full_path)
            except Exception as e:
                print(f"[!] Failed to delete {full_path}: {e}")

def generate_ssh_log():
    return f"{datetime.now().isoformat()} Failed password for {fake.user_name()} from {fake.ipv4()} port {random.randint(1024,65535)} ssh2\n"

def generate_file_content():
    kind = random.choice(['text', 'banner', 'ssh_log', 'password', 'api_key'])

    if kind == 'text':
        return fake.text(max_nb_chars=random.randint(100, 1000))
    elif kind == 'banner':
        return random.choice(FAKE_BANNERS)
    elif kind == 'ssh_log':
        return ''.join(generate_ssh_log() for _ in range(random.randint(3, 10)))
    elif kind == 'password':
        return '\n'.join(FAKE_PASSWORDS)
    elif kind == 'api_key':
        return '\n'.join(FAKE_API_KEYS)
    return ""

def generate_bait_file(directory, index):
    ext = random.choice(FILE_EXTENSIONS)
    name = fake.file_name(extension=ext.strip('.'))
    filename = name  # No "bait_" prefix — realistic file names
    filepath = os.path.join(directory, filename)
    content = generate_file_content()
    with open(filepath, "w") as f:
        f.write(content)
    return filepath

def populate_all():
    for honeypot, bait_dir in HONEYPOT_BAIT_DIRS.items():
        os.makedirs(bait_dir, exist_ok=True)
        print(f"[*] Populating bait for: {honeypot}")
        for i in range(300):  # Change to 1000 if you want more
            path = generate_bait_file(bait_dir, i)
        print(f"[+] Done: {bait_dir}")

if __name__ == "__main__":
    populate_all()