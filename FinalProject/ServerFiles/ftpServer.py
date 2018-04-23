from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

authorizer = DummyAuthorizer()
authorizer.add_user("user", "12345", "temp", perm="elradfmwMT")
authorizer.add_user("g7", "g7", "temp", perm="elradfmwMT")


handler = FTPHandler
handler.authorizer = authorizer

server = FTPServer(("127.0.0.1", 2121), handler)
server.serve_forever()



