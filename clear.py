def chop_word(s):
    for i, _ in enumerate(s):
        letter = s[i:i+1]
        if letter not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_":
            return s[:i]

to_clear = {}
files_methods = {}
files_functions = {}
for session_number in range(3):
    session = f"session{session_number}"
    with open(f"{session}/complete/answers.py", "r") as file:
        parse = False
        for raw_line in file:
            line = raw_line.strip()
            if line == '"""':
                parse = False
            if parse:
                to_clear[line] = 1
                components = line.split('.')
                if len(components) == 3:
                    files_methods[components[0]] = 1
                else:
                    files_functions[components[0]] = 1
            if line == 'FUNCTIONS = """':
                parse = True
    for filename in files_functions.keys():
        modified_file = ""
        with open(f"{session}/{filename}.py", "r") as file:
            current_func = None
            active = False
            for line in file:
                if line == "\n":
                    if active:
                        modified_file += "    raise NotImplementedError\n"
                        active = False
                    if current_func:
                        current_func = None
                if active:
                    if line.lstrip().startswith("#") or line.lstrip().startswith("\"\"\""):
                        modified_file += line
                else:
                    modified_file += line
                if line.startswith("def "):
                    current_func = chop_word(line.lstrip()[4:])
                    key = f"{filename}.{current_func}"
                    if to_clear.get(key):
                        active = True
        with open(f"{session}/{filename}.py", "w") as file:
            file.write(modified_file)
    for filename in files_methods.keys():
        modified_file = ""
        with open(f"{session}/{filename}.py", "r") as file:
            current_class = None
            current_func = None
            active = False
            for line in file:
                if line == "\n":
                    if active:
                        modified_file += "        raise NotImplementedError\n"
                        active = False
                    if current_func:
                        current_func = None
                    elif current_class:
                        current_class = None
                if active:
                    if line.lstrip().startswith("#") or line.lstrip().startswith("\"\"\""):
                        modified_file += line
                else:
                    modified_file += line
                if line.startswith("class "):
                    current_class = chop_word(line[6:])
                if line.startswith("    def "):
                    current_func = chop_word(line.lstrip()[4:])
                    key = f"{filename}.{current_class}.{current_func}"
                    if to_clear.get(key):
                        active = True
        with open(f"{session}/{filename}.py", "w") as file:
            file.write(modified_file)
    
