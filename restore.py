from shutil import copy
import sys

sessions = [int(a) for a in sys.argv[1:]]
if len(sessions) == 0:
    sessions = range(5)

for session_number in sessions:
    session = f"session{session_number}"
    filenames = {}
    with open(f"{session}/complete/answers.py", "r") as file:
        parse = False
        for raw_line in file:
            line = raw_line.strip()
            if line == '"""':
                parse = False
            if parse:
                components = line.split('.')
                filenames[components[0]] = True
            if line == 'FUNCTIONS = """':
                parse = True
    for filename in filenames.keys():
        print(f"{session}/complete/{filename}.py")
        copy(f"{session}/complete/{filename}.py", f"{session}/{filename}.py")
