from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider

if __name__ == '__main__':
    auth_provider = PlainTextAuthProvider(username='scylla_user', password='not_cassandra')
    cluster = Cluster(auth_provider=auth_provider, protocol_version=2)
    session = cluster.connect()

    session.execute("DELETE FROM system_auth.roles where role='scylla_user'")

    rows = session.execute('SELECT * FROM system_auth.roles')
    for user_row in rows:
        print(user_row)
