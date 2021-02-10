import sys
import stat
import os
from os import chmod as chmoooood
import pickle
import tempfile
import socket

def is_admin(user):
    """
    Bad practice because running Python in optimized mode would bypass this check
    https://pycharm-security.readthedocs.io/en/latest/checks/AST100.html
    In production environments, the python -O optimization flag is often used, which bypasses assert statements.
    """
    assert user.is_admin


def run_arbitrary_code():
    """
    Bad idea.
    https://pycharm-security.readthedocs.io/en/latest/checks/EX100.html
    """
    exec(sys.argv[1])


def bad_permissions():
    """
    Bad for Unix environments.
    """
    os.chmod('x', 777)

    os.chmod('x', 0o777)

    os.chmod('x', 0o300)

    os.chmod('x', stat.S_IXOTH | stat.S_IXGRP)
    os.chmod('x', stat.S_IXOTH)
    os.chmod('x', stat.S_IRUSR | stat.S_IRGRP | stat.S_IWUSR | stat.S_IXOTH)

    # Try and fool some static analysis tools, but still works.
    chmoooood('x', 777)


def pickles(f):
    """
    Loading serialized data with the pickle module can expose arbitrary code execution using the reduce method.

    Before objects are serialised, they can have a custom __reduce__ method attribute, which will execute on expansion during the pickle loader.

    This can be used to injection malicious data into serialized data.

    Because pickle is often used for caching or storing python objects by serialization, attackers will use this flaw to write arbitrary code to execute on the host.
    """

    with open(f) as input:
        python_objects = pickle.load(input)


def tmp():
    """
    The way that tempfile.mktemp creates temporary files is insecure and leaves it open to attackers replacing the file contents. Use tempfile.mkstemp instead."
    """
    f = tempfile.mktemp()  # Should not be useds

    """
    Using a hardcoded path to read or write temporary files is insecure and leaves it open to attackers replacing the file contents.
    """
    with open('/tmp/my_app', 'w') as tmp_file:
        tmp_file.write('data')


def try_except_pass():
    """
    Use of a try … except block where the except block does not contain anything other than comments and a pass statement is considered bad security practice.

    Whilst an attacker may be trying to exploit exceptions in your code, you should, at the very least, log these exceptions.

    Some runtime errors that may be caused by insufficient permissions should not be allowed to continue control flow, and should stop execution of the program.

    This will only apply to the generic explicit Exception except type, or an empty except type.
    """
    try:
        do_things()
    except:
        # do nothing!
        pass

def bind_all_the_interfaces_correct_pattern():
    """Use Context Managers (best practice)"""
    # Bad
    with socket.socket(family=socket.AddressFamily.AF_INET) as sock:
        sock.bind(("", 43))
    # BAd
    with socket.socket(family=socket.AddressFamily.AF_INET) as sock:
        sock.bind(("0.0.0.0", 45))
    # Bad
    with socket.socket(family=socket.AddressFamily.AF_INET6) as sock:
        sock.bind(("::", 46))
    # Bad
    with socket.socket(family=socket.AddressFamily.AF_INET6) as sock:
        sock.bind(("0:0:0:0:0:0:0:0", 47))
    # ok
    with socket.socket(family=socket.AddressFamily.AF_INET) as sock:
        sock.bind(("127.0.0.1", 48))


def bind_all_the_interfaces():
    # Bad
    sock = socket.socket(family=socket.AddressFamily.AF_INET)
    sock.bind(("", 43))
    # BAd
    sock2 = socket.socket(family=socket.AddressFamily.AF_INET)
    sock2.bind(("0.0.0.0", 45))
    # Bad
    sock3 = socket.socket(family=socket.AddressFamily.AF_INET6)
    sock3.bind(("::", 46))
    # Bad
    sock4 = socket.socket(family=socket.AddressFamily.AF_INET6)
    sock4.bind(("0:0:0:0:0:0:0:0", 47))
    # ok
    sock5 = socket.socket(family=socket.AddressFamily.AF_INET)
    sock5.bind(("127.0.0.1", 48))
