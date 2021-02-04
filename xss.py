from jinja2 import Template
from jinja2 import Environment, PackageLoader
from mako.template import Template as MakoTemplate

t = Template("<html><body> Hello {{person}}</body></html>")
t.render(person="<script type='javascript'>alert('I am an XSS flaw!')</script>")

env = Environment(
    loader=PackageLoader('yourapplication', 'templates'),
)
template = env.get_template('mytemplate.html')
template.render(person="<script type='javascript'>alert('I am an XSS flaw!')</script>")


t = MakoTemplate("<html><body> Hello ${ person }</body></html>")
t.render(person="<script type='javascript'>alert('I am an XSS flaw!')</script>")
