import subprocess
import time
import os
import signal

# Define paths to your scripts
SCRIPTS = [
    r"C:\Users\gokul\Downloads\iot_code\netflow.py",
    r"C:\Users\gokul\Downloads\iot_code\payload.py",
    r"C:\Users\gokul\Downloads\iot_code\topology.py"
]

# Store process references
processes = []

try:
    print("Starting all monitoring modules...\n")
    for script in SCRIPTS:
        p = subprocess.Popen(["python", script])
        processes.append((script, p))
        print(f"Started: {script} (PID: {p.pid})")

    # Keep the main process alive to manage children
    while True:
        time.sleep(5)
        for i, (script, p) in enumerate(processes):
            if p.poll() is not None:  # Process has exited
                print(f"\n{script} crashed. Restarting...")
                new_proc = subprocess.Popen(["python", script])
                processes[i] = (script, new_proc)
                print(f"Restarted: {script} (PID: {new_proc.pid})")

except KeyboardInterrupt:
    print("\nShutting down all processes...")
    for script, p in processes:
        try:
            os.kill(p.pid, signal.SIGTERM)
            print(f"Terminated: {script} (PID: {p.pid})")
        except Exception as e:
            print(f"Failed to kill {script}: {e}")
