import nbformat
import re
import sys

sessions = [0,1,2]

FIRST_CELL = '''############## PLEASE RUN THIS CELL FIRST! ###################

# import everything and define a test runner function
from importlib import reload
from helper import run
'''

UNITTEST_TEMPLATE_1 = '''### Exercise {exercise_number}

{instructions}

#### Make [this test](/edit/{path}/{module}.py) pass: `{module}.py:{test_suite}:{test}`'''


UNITTEST_TEMPLATE_2 = '''# Exercise {exercise_number}

reload({module})
run({module}.{test_suite}('{test}'))'''


UNITTEST_TEMPLATE_3 = """# Exercise {exercise_number}

reload({module})
reload(script)
run({module}.{test_suite}('{test}'))"""


EXERCISE_TEMPLATE_1 = '''### Exercise {exercise_number}
{instructions}'''


EXERCISE_TEMPLATE_2 = '''# Exercise {exercise_number}

{code}'''


for session in sessions:
    notebook = nbformat.v4.new_notebook()
    notebook_complete = nbformat.v4.new_notebook()
    cells = notebook['cells']
    cells_complete = notebook_complete['cells']
    path = f'session{session}'
    with open('{}/complete/answers.py'.format(path), 'r') as f:
        current = ''
        cell_type = None
        exercise_number = 1
        for l in f:
            line = l.strip()
            if line in ('#markdown', '#code', '#exercise', '#unittest'):
                cell_type = line[1:]
            elif line == '#end{}'.format(cell_type):
                if cell_type == 'markdown':
                    markdown_cell = nbformat.v4.new_markdown_cell(current)
                    markdown_cell.metadata['slideshow'] = dict(slide_type='slide')
                    cells.append(markdown_cell)
                    cells_complete.append(markdown_cell)
                elif cell_type == 'code':
                    # only take >>> or ... lines
                    lines = []
                    for line in current.split('\n'):
                        if line.startswith('>>> ') or line.startswith('... '):
                            line = re.sub(r'\\\\x', r'\\x', line)
                            lines.append(line[4:])
                    if lines[0].startswith('import '):
                        code = FIRST_CELL + '\n'.join(lines)
                        slide_type = 'skip'
                    else:
                        code = '\n'.join(lines)
                        slide_type = 'slide'
                    code_cell = nbformat.v4.new_code_cell(code)
                    code_cell.metadata['slideshow'] = dict(slide_type=slide_type)
                    cells.append(code_cell)
                    cells_complete.append(code_cell)
                elif cell_type == 'exercise':
                    instructions, code = current.split('---')
                    markdown = EXERCISE_TEMPLATE_1.format(
                        exercise_number=exercise_number,
                        instructions=instructions,
                    )
                    markdown_cell = nbformat.v4.new_markdown_cell(markdown)
                    markdown_cell.metadata['slideshow'] = dict(slide_type='slide')
                    cells.append(markdown_cell)
                    cells_complete.append(markdown_cell)
                    lines = []
                    lines_complete = []
                    for line in code.split('\n'):
                        if line.startswith('>>> ') or line.startswith('... '):
                            line = re.sub(r'\\\\x', r'\\x', line)
                            start_alt = line.find('  #/')
                            if start_alt == -1:
                                lines.append(line[4:])
                                lines_complete.append(line[4:])
                            else:
                                lines.append(line[start_alt+4:])
                                lines_complete.append(line[4:start_alt])
                    code_1 = EXERCISE_TEMPLATE_2.format(
                        code='\n'.join(lines),
                        exercise_number=exercise_number,
                    )
                    code_cell_1 = nbformat.v4.new_code_cell(code_1)
                    cells.append(code_cell_1)
                    code_2 = EXERCISE_TEMPLATE_2.format(
                        code='\n'.join(lines_complete),
                        exercise_number=exercise_number,
                    )
                    code_cell_2 = nbformat.v4.new_code_cell(code_2)
                    cells_complete.append(code_cell_2)
                    exercise_number += 1
                elif cell_type == 'unittest':
                    module, test_suite, test, instructions = current.split(':', 3)
                    markdown = UNITTEST_TEMPLATE_1.format(
                        exercise_number=exercise_number,
                        instructions=instructions,
                        module=module,
                        path=path,
                        test=test,
                        test_suite=test_suite,
                    )
                    markdown_cell = nbformat.v4.new_markdown_cell(markdown)
                    markdown_cell.metadata['slideshow'] = dict(slide_type='slide')
                    cells.append(markdown_cell)
                    cells_complete.append(markdown_cell)
                    if module == "op":
                        template = UNITTEST_TEMPLATE_3
                    else:
                        template = UNITTEST_TEMPLATE_2
                    code = template.format(
                        exercise_number=exercise_number,
                        module=module,
                        path=path,
                        test=test,
                        test_suite=test_suite,
                    )
                    code_cell = nbformat.v4.new_code_cell(code)
                    cells.append(code_cell)
                    cells_complete.append(code_cell)
                    exercise_number += 1
                current = ''
                cell_type = None
            elif cell_type:
                if cell_type == 'markdown':
                    current += l
                else:
                    current += line + '\n'
    nbformat.write(notebook, '{}/session{}.ipynb'.format(path, session))
    nbformat.write(notebook_complete, '{}/complete/session{}.ipynb'.format(path, session))
