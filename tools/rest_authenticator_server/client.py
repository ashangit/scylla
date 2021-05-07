from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider


def contact_scylla():
    auth_provider = PlainTextAuthProvider(username='scylla_user', password='not_cassandra')
    cluster = Cluster(auth_provider=auth_provider, protocol_version=2)
    session = cluster.connect()
    try:
        print('roles')
        rows = session.execute('SELECT * FROM system_auth.roles')
        for user_row in rows:
            print(user_row)

        print('role_members')
        rows = session.execute('SELECT * FROM system_auth.role_members')
        for user_row in rows:
            print(user_row)

        print('Delete scylla role')
        session.execute("DELETE FROM system_auth.roles where role='scylla_user'")

        # print('role_permissions')
        # rows = session.execute('SELECT * FROM system_auth.role_permissions')
        # for user_row in rows:
        #    print(user_row)

        # print(session.execute('LIST ALL PERMISSIONS OF scylla_user;'))
        # rows = session.execute('LIST ROLES OF scylla_user;')
        # for user_row in rows:
        #    print(user_row)
    finally:
        session.shutdown()


if __name__ == '__main__':
    for i in range(2):
        contact_scylla()
