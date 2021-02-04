from django.db import connection
from django.db.models.expressions import RawSQL
from django.db import connection
from django.utils.safestring import mark_safe
from django.contrib.auth.models import User
from django.shortcuts import render


def my_view(self, lname, someparam):
    # this is bad
    User.objects.raw("SELECT * FROM myapp_person WHERE last_name = %s" % lname)
    # this bypasses Django's SQL injection protection, but harder to detect
    User.objects.raw("SELECT * FROM myapp_person WHERE last_name = '%s'", [lname])

    qs = User.objects

    
    qs.annotate(val=RawSQL("select col from sometable where othercol = '%s'", (someparam,)))  # this is bad!

    User.objects.raw("SELECT * FROM myapp_person WHERE last_name = '%s'", [lname])  # this is also bad!

    # These two are still SQLi but harder to detect
    qs.extra(
        select={'val': "select col from sometable where othercol = '%s'"},
        select_params=(someparam,),
    )
    User.objects.extra(where=['headline="%s"'], params=['Lennon'])


def cursor_examples(self):
    with connection.cursor() as cursor:
        cursor.execute("UPDATE bar SET foo = 1 WHERE baz = %s", [self.baz])  # OK
        cursor.execute("SELECT foo FROM bar WHERE baz = '%s'", [self.baz])  # BAD, SQLi
        row = cursor.fetchone()
    return row

def xss_view(mystr):
    mystr = mark_safe(mystr)
    return render(mystr)

