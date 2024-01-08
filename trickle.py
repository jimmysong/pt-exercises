from os.path import exists
from shutil import copy
import sys

filenames = [a + ".py" for a in sys.argv[1:]]

for session_number in range(4):
    session = f"session{session_number}"
    for filename in filenames:
        print(f"{filename}")
        target = f"{session}/complete/{filename}"
        if exists(target):
            copy(f"session4/complete/{filename}", target)
