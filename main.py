import subprocess
import time

def run_script(script_name):
    try:
        subprocess.run(['python', script_name], check=True)
    except subprocess.CalledProcessError:
        print(f"Error running {script_name}")

if __name__ == "__main__":
    # Run AuthServer.py
    run_script("AuthServer.py")

    # Add a delay to ensure that AuthServer.py has started before running the other scripts
    time.sleep(2)

    # Run Message.py
    run_script("MessageServer.py")

    # Run client.py
    run_script("client.py")