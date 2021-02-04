import subprocess
import sys
from shlex import quote as shlex_quote
import paramiko
import shlex
import os
import commands
import posix
import popen2

def get_opts(opt):
    # who knows what might happen here
    return 'x'


def main(opt):
    # these are all very, very bad.
    subprocess.call(opt, shell=True)
    subprocess.run(opt, shell=True)
    subprocess.Popen(opt, shell=True)

    # this is less-bad because its being escaped, but bandit doesnt care
    subprocess.call(shlex_quote(opt), shell=True)


def paramiko_shell_injection(input):
    client = paramiko.SSHClient()
    # This is bad because its not being escaped.
    ret = client.exec_command(input)

def legacy_shell_injections(input):
    """ 
    Numerous legacy APIs for shells in Python stdlib
    """
    os.system(input)
    os.popen(input)
    os.popen2(input)
    os.popen3(input)
    os.popen4(input)
    posix.system(input)
    posix.popen(input)
    popen2.popen2(input)
    popen2.popen3(input)
    popen2.popen4(input)
    popen2.Popen3(input)
    popen2.Popen4(input)
    commands.getoutput(input)
    commands.getstatusoutput(input)


def legacy_spawn_apis(proc, args):
    """
    Deprecated APIs, but still possible attacks
    """
    os.execl(proc, args)
    os.execl(proc, args)
    os.execle(proc, args)
    os.execlp(proc, args)
    os.execlpe(proc, args)
    os.execv(proc, args)
    os.execve(proc, args)
    os.execvp(proc, args)
    os.execvpe(proc, args)
    os.spawnl(proc, args)
    os.spawnle(proc, args)
    os.spawnlp(proc, args)
    os.spawnlpe(proc, args)
    os.spawnv(proc, args)
    os.spawnve(proc, args)
    os.spawnvp(proc, args)
    os.spawnvpe(proc, args)


if __name__ == "__main__":
    main(sys.argv[1])
