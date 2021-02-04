from sqlalchemy import create_engine, select
from sqlalchemy import Table, Column, Integer, String, MetaData, ForeignKey
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import logging


def formatted_queries():
    """
    A selection of bobby-tables queries
    """

    id = get_id()  # Could be a SQLi response..

    query1 = f"SELECT * FROM users WHERE id = {id}"

    query2 = "SELECT * FROM users WHERE id = {0}" % id

    query3 = "SELECT * FROM users WHERE id = {0}".format(id)

    query4 = f"UPDATE users SET is_admin = 1 WHERE id = {id}"

    query5 = f"DELETE FROM users WHERE id = {id}"

    query6 = f"INSERT INTO users (id) VALUES ( id = {id} )"

    query7 = f"SELECT * FROM users WHERE id = {id}"


def sql_achemy_():
    logging.basicConfig()
    logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
    Base = declarative_base()


    class User(Base):
        __tablename__ = 'users'
        id = Column(Integer, primary_key=True)
        name = Column(String)
        fullname = Column(String)


    test_engine = create_engine('sqlite:///:memory:', echo=True)
    Session = sessionmaker(bind=test_engine)

    session = Session()

    metadata = MetaData()
    users = Table('users', metadata,
        Column('id', Integer, primary_key=True),
        Column('name', String),
        Column('fullname', String),
    )

    addresses = Table('addresses', metadata,
        Column('id', Integer, primary_key=True),
        Column('user_id', None, ForeignKey('users.id')),
        Column('email_address', String, nullable=False)
    )
    metadata.create_all(test_engine)

    with test_engine.connect() as conn:
        conn.execute(users.insert(), [
            {'id': 1, 'name': 'jack'},
            {'id': 2, 'name': 'jill'},
            {'id': 3, 'name': 'sally'},
            {'id': 4, 'name': 'sue'},
        ])
        conn.execute(addresses.insert(), [
            {'user_id': 1, 'email_address' : 'jack@yahoo.com'},
            {'user_id': 2, 'email_address' : 'jack@msn.com'},
            {'user_id': 3, 'email_address' : 'www@www.org'},
            {'user_id': 4, 'email_address' : 'wendy@aol.com'},
        ])
        data = ( {'user_id': 1, 'email_address' : 'jack@yahoo.com\''},)
        # This is bad. but it will be caught by SQL100
        statement = text("""INSERT INTO addresses(user_id, email_address) VALUES({}, :email_address)""".format(1))
        for line in data:
            conn.execute(statement, **line)

        # This is also bad. but it will be caught by caught by SQL100
        conn.execute("SELECT email_address FROM addresses WHERE email_address = \'{}\'".format('anthony@x.com'))

        session.query(User).filter(User.name == "bob \"'`OR 1=1").all()  # This won't have any effect

        part = "id<224 OR 1=1"  # exploitable, can override the original filter.
        _x = session.query(User).filter(User.id == 1).filter(text(part)).all()  # This will cause all sorts of trouble
        if len(_x) > 1:
            print("Proven exploit!")

        suffix = " OR 1=1"  # Example exploiting suffix to add/change WHERE clause
        prefix = " *,"  # Example exploiting query to get all fields
        stmt = select([users.c.name]).where(users.c.id == 1).suffix_with(suffix, dialect="sqlite")
        conn.execute(stmt)

        stmt2 = select([addresses]).prefix_with(prefix)  # can be chained
        conn.execute(stmt2)