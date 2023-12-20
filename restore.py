from shutil import copy

for session_number in range(3):
    session = f"session{session_number}"
    file_names = {}
    with open(f"{session}/complete/answers.py", "r") as file:
        parse = False
        for raw_line in file:
            line = raw_line.strip()
            if line == '"""':
                parse = False
            if parse:
                components = line.split('.')
                file_names[components[0]] = True
            if line == 'FUNCTIONS = """':
                parse = True
    for filename in file_names.keys():
        copy(f"{session}/complete/{filename}.py", f"{session}/{filename}.py")
