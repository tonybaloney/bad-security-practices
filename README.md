# bad-security-practices

A Python goat.

There are around 80 unique security bugs in this project.

## Bandit

Bandit *.py reports 64 issues

<details>
  <p>
    
```default


Test results:
>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Low
   Location: django.py:11
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b608_hardcoded_sql_expressions.html
10          # this is bad
11          User.objects.raw("SELECT * FROM myapp_person WHERE last_name = %s" % lname)
12          # this bypasses Django's SQL injection protection, but harder to detect

--------------------------------------------------
>> Issue: [B703:django_mark_safe] Potential XSS on mark_safe function.
   Severity: Medium   Confidence: High
   Location: django.py:38
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b703_django_mark_safe.html
37      def xss_view(mystr):
38          mystr = mark_safe(mystr)
39          return render(mystr)

--------------------------------------------------
>> Issue: [B308:blacklist] Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.
   Severity: Medium   Confidence: High
   Location: django.py:38
   More Info: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b308-mark-safe
37      def xss_view(mystr):
38          mystr = mark_safe(mystr)
39          return render(mystr)

--------------------------------------------------
>> Issue: [B324:hashlib_new] Use of insecure MD4 or MD5 hash function.
   Severity: Medium   Confidence: High
   Location: encryption.py:4
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b324_hashlib_new.html
3       # Use of weak hashers is bad (discouraged!)
4       hashlib.new('md5')
5       hashlib.md4()

--------------------------------------------------
>> Issue: [B303:blacklist] Use of insecure MD2, MD4, MD5, or SHA1 hash function.
   Severity: Medium   Confidence: High
   Location: encryption.py:6
   More Info: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b303-md5
5       hashlib.md4()
6       hashlib.md5()
7       hashlib.new('sha1')

--------------------------------------------------
>> Issue: [B324:hashlib_new] Use of insecure MD4 or MD5 hash function.
   Severity: Medium   Confidence: High
   Location: encryption.py:7
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b324_hashlib_new.html
6       hashlib.md5()
7       hashlib.new('sha1')
8       hashlib.sha1()

--------------------------------------------------
>> Issue: [B303:blacklist] Use of insecure MD2, MD4, MD5, or SHA1 hash function.
   Severity: Medium   Confidence: High
   Location: encryption.py:8
   More Info: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b303-md5
7       hashlib.new('sha1')
8       hashlib.sha1()
9       

--------------------------------------------------
>> Issue: [B403:blacklist] Consider possible security implications associated with pickle module.
   Severity: Low   Confidence: High
   Location: general.py:5
   More Info: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b403-import-pickle
4       from os import chmod as chmoooood
5       import pickle
6       import tempfile

--------------------------------------------------
>> Issue: [B101:assert_used] Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
   Severity: Low   Confidence: High
   Location: general.py:15
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b101_assert_used.html
14          """
15          assert user.is_admin
16      

--------------------------------------------------
>> Issue: [B102:exec_used] Use of exec detected.
   Severity: Medium   Confidence: High
   Location: general.py:23
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b102_exec_used.html
22          """
23          exec(sys.argv[1])
24      

--------------------------------------------------
>> Issue: [B103:set_bad_file_permissions] Chmod setting a permissive mask 01411 on file (x).
   Severity: Medium   Confidence: High
   Location: general.py:30
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b103_set_bad_file_permissions.html
29          """
30          os.chmod('x', 777)
31      

--------------------------------------------------
>> Issue: [B103:set_bad_file_permissions] Chmod setting a permissive mask 0777 on file (x).
   Severity: High   Confidence: High
   Location: general.py:32
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b103_set_bad_file_permissions.html
31      
32          os.chmod('x', 0o777)
33      

--------------------------------------------------
>> Issue: [B103:set_bad_file_permissions] Chmod setting a permissive mask 01411 on file (x).
   Severity: Medium   Confidence: High
   Location: general.py:41
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b103_set_bad_file_permissions.html
40          # Try and fool some static analysis tools, but still works.
41          chmoooood('x', 777)
42      

--------------------------------------------------
>> Issue: [B301:blacklist] Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.
   Severity: Medium   Confidence: High
   Location: general.py:56
   More Info: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b301-pickle
55          with open(f) as input:
56              python_objects = pickle.load(input)
57      

--------------------------------------------------
>> Issue: [B306:blacklist] Use of insecure and deprecated function (mktemp).
   Severity: Medium   Confidence: High
   Location: general.py:63
   More Info: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b306-mktemp-q
62          """
63          f = tempfile.mktemp()  # Should not be useds
64      

--------------------------------------------------
>> Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory.
   Severity: Medium   Confidence: Medium
   Location: general.py:68
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b108_hardcoded_tmp_directory.html
67          """
68          with open('/tmp/my_app', 'w') as tmp_file:
69              tmp_file.write('data')

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   Location: general.py:84
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b110_try_except_pass.html
83              do_things()
84          except:
85              # do nothing!
86              pass
87      

--------------------------------------------------
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'NODFGODFG'
   Severity: Low   Confidence: Medium
   Location: passwords.py:3
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html
2       # Storing tokens and passwords in string literals is bad
3       password = "NODFGODFG"
4       token = "ASDFSFGDG"

--------------------------------------------------
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'ASDFSFGDG'
   Severity: Low   Confidence: Medium
   Location: passwords.py:4
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html
3       password = "NODFGODFG"
4       token = "ASDFSFGDG"
5       secret = "SDHGFHFDG"

--------------------------------------------------
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'SDHGFHFDG'
   Severity: Low   Confidence: Medium
   Location: passwords.py:5
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html
4       token = "ASDFSFGDG"
5       secret = "SDHGFHFDG"
6       
7       # Comparing with EQ is bad for timing attacks
8       if password == "SUPER_SECRET": 

--------------------------------------------------
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'SUPER_SECRET'
   Severity: Low   Confidence: Medium
   Location: passwords.py:8
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html
7       # Comparing with EQ is bad for timing attacks
8       if password == "SUPER_SECRET": 
9         proceed()

--------------------------------------------------
>> Issue: [B506:yaml_load] Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().
   Severity: Medium   Confidence: High
   Location: serialization.py:13
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b506_yaml_load.html
12      with open('foo.yml') as f:
13          data = load(f)
14      

--------------------------------------------------
>> Issue: [B506:yaml_load] Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().
   Severity: Medium   Confidence: High
   Location: serialization.py:16
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b506_yaml_load.html
15      with open('foo.yml') as f:
16          data = yaml.load(f)
17      

--------------------------------------------------
>> Issue: [B408:blacklist] Using parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parse with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.
   Severity: Low   Confidence: High
   Location: serialization.py:19
   More Info: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b408-import-xml-minidom
18      
19      from xml.dom.minidom import parse, parseString
20      
21      
22      x = """

--------------------------------------------------
>> Issue: [B318:blacklist] Using xml.dom.minidom.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.minidom.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called
   Severity: Medium   Confidence: High
   Location: serialization.py:38
   More Info: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b313-b320-xml-bad-minidom
37      
38      parse(x)  # bad. goes boom
39      parseString(x)  # bad. goes bang

--------------------------------------------------
>> Issue: [B318:blacklist] Using xml.dom.minidom.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.minidom.parseString with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called
   Severity: Medium   Confidence: High
   Location: serialization.py:39
   More Info: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b313-b320-xml-bad-minidom
38      parse(x)  # bad. goes boom
39      parseString(x)  # bad. goes bang

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with subprocess module.
   Severity: Low   Confidence: High
   Location: shell_injection.py:1
   More Info: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b404-import-subprocess
1       import subprocess
2       import sys
3       from shlex import quote as shlex_quote

--------------------------------------------------
>> Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:18
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html
17          # these are all very, very bad.
18          subprocess.call(opt, shell=True)
19          subprocess.run(opt, shell=True)

--------------------------------------------------
>> Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:19
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html
18          subprocess.call(opt, shell=True)
19          subprocess.run(opt, shell=True)
20          subprocess.Popen(opt, shell=True)

--------------------------------------------------
>> Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:20
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html
19          subprocess.run(opt, shell=True)
20          subprocess.Popen(opt, shell=True)
21      

--------------------------------------------------
>> Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:23
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html
22          # this is less-bad because its being escaped, but bandit doesnt care
23          subprocess.call(shlex_quote(opt), shell=True)
24      

--------------------------------------------------
>> Issue: [B601:paramiko_calls] Possible shell injection via Paramiko call, check inputs are properly sanitized.
   Severity: Medium   Confidence: Medium
   Location: shell_injection.py:29
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b601_paramiko_calls.html
28          # This is bad because its not being escaped.
29          ret = client.exec_command(input)
30      

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:35
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
34          """
35          os.system(input)
36          os.popen(input)

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:36
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
35          os.system(input)
36          os.popen(input)
37          os.popen2(input)

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:37
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
36          os.popen(input)
37          os.popen2(input)
38          os.popen3(input)

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:38
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
37          os.popen2(input)
38          os.popen3(input)
39          os.popen4(input)

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:39
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
38          os.popen3(input)
39          os.popen4(input)
40          posix.system(input)

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:42
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
41          posix.popen(input)
42          popen2.popen2(input)
43          popen2.popen3(input)

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:43
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
42          popen2.popen2(input)
43          popen2.popen3(input)
44          popen2.popen4(input)

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:44
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
43          popen2.popen3(input)
44          popen2.popen4(input)
45          popen2.Popen3(input)

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:45
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
44          popen2.popen4(input)
45          popen2.Popen3(input)
46          popen2.Popen4(input)

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:46
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
45          popen2.Popen3(input)
46          popen2.Popen4(input)
47          commands.getoutput(input)

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:47
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
46          popen2.Popen4(input)
47          commands.getoutput(input)
48          commands.getstatusoutput(input)

--------------------------------------------------
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   Location: shell_injection.py:48
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html
47          commands.getoutput(input)
48          commands.getstatusoutput(input)
49      

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:55
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
54          """
55          os.execl(proc, args)
56          os.execl(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:56
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
55          os.execl(proc, args)
56          os.execl(proc, args)
57          os.execle(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:57
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
56          os.execl(proc, args)
57          os.execle(proc, args)
58          os.execlp(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:58
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
57          os.execle(proc, args)
58          os.execlp(proc, args)
59          os.execlpe(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:59
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
58          os.execlp(proc, args)
59          os.execlpe(proc, args)
60          os.execv(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:60
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
59          os.execlpe(proc, args)
60          os.execv(proc, args)
61          os.execve(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:61
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
60          os.execv(proc, args)
61          os.execve(proc, args)
62          os.execvp(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:62
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
61          os.execve(proc, args)
62          os.execvp(proc, args)
63          os.execvpe(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:63
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
62          os.execvp(proc, args)
63          os.execvpe(proc, args)
64          os.spawnl(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:64
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
63          os.execvpe(proc, args)
64          os.spawnl(proc, args)
65          os.spawnle(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:65
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
64          os.spawnl(proc, args)
65          os.spawnle(proc, args)
66          os.spawnlp(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:66
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
65          os.spawnle(proc, args)
66          os.spawnlp(proc, args)
67          os.spawnlpe(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:67
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
66          os.spawnlp(proc, args)
67          os.spawnlpe(proc, args)
68          os.spawnv(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:68
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
67          os.spawnlpe(proc, args)
68          os.spawnv(proc, args)
69          os.spawnve(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:69
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
68          os.spawnv(proc, args)
69          os.spawnve(proc, args)
70          os.spawnvp(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:70
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
69          os.spawnve(proc, args)
70          os.spawnvp(proc, args)
71          os.spawnvpe(proc, args)

--------------------------------------------------
>> Issue: [B606:start_process_with_no_shell] Starting a process without a shell.
   Severity: Low   Confidence: Medium
   Location: shell_injection.py:71
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b606_start_process_with_no_shell.html
70          os.spawnvp(proc, args)
71          os.spawnvpe(proc, args)
72      

--------------------------------------------------
>> Issue: [B104:hardcoded_bind_all_interfaces] Possible binding to all interfaces.
   Severity: Medium   Confidence: Medium
   Location: xmlrpcbackdoor.py:4
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b104_hardcoded_bind_all_interfaces.html
3       
4       with SimpleXMLRPCServer(('0.0.0.0', 8000),) as server:
5           class MyFuncs:

--------------------------------------------------
>> Issue: [B701:jinja2_autoescape_false] By default, jinja2 sets autoescape to False. Consider using autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.
   Severity: High   Confidence: High
   Location: xss.py:8
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b701_jinja2_autoescape_false.html
7       
8       env = Environment(
9           loader=PackageLoader('yourapplication', 'templates'),
10      )

--------------------------------------------------
>> Issue: [B702:use_of_mako_templates] Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks. Ensure variables in all templates are properly sanitized via the 'n', 'h' or 'x' flags (depending on context). For example, to HTML escape the variable 'data' do ${ data |h }.
   Severity: Medium   Confidence: High
   Location: xss.py:15
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b702_use_of_mako_templates.html
14      
15      t = MakoTemplate("<html><body> Hello ${ person }</body></html>")
16      t.render(person="<script type='javascript'>alert('I am an XSS flaw!')</script>")

--------------------------------------------------

Code scanned:
        Total lines of code: 285
        Total lines skipped (#nosec): 0

Run metrics:
        Total issues (by severity):
                Undefined: 0
                Low: 26
                Medium: 20
                High: 18
        Total issues (by confidence):
                Undefined: 0
                Low: 1
                Medium: 24
                High: 39
Files skipped (1):
        sql.py (syntax error while parsing AST from file)


```
</p> </details>
