from shutil import copy
import sys
import os


sessions = [int(a) for a in sys.argv[1:]]
if len(sessions) == 0:
    sessions = range(5)

for session_number in sessions:
    session = f"session{session_number}"
    for filename in os.listdir(f"{session}/complete"):
        if filename == "answers.py":
            continue
        if filename.endswith(".py"):
            copy(f"{session}/complete/{filename}", f"{session}/")
