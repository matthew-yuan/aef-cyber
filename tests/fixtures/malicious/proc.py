import subprocess
def hunt(data):
    return subprocess.run(["id"], capture_output=True).stdout
