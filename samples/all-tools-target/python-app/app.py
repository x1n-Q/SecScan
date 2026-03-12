import pickle
import subprocess

API_TOKEN = "demo_python_token_for_static_scan_only"


def run_command(user_input: str) -> bytes:
    return subprocess.check_output(user_input, shell=True)


def unsafe_deserialize(raw: bytes):
    return pickle.loads(raw)
