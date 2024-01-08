from os import chdir
from subprocess import call


for session in range(5):
    chdir("session{}/complete".format(session))
    call("pytest --disable-warnings --doctest-modules *.py", shell=True)
    chdir("../..")
