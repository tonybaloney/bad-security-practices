from xmlrpc.server import SimpleXMLRPCServer


with SimpleXMLRPCServer(('0.0.0.0', 8000),) as server:
    class MyFuncs:
        def mul(self, x, y):
            return x * y

    server.register_instance(MyFuncs(), allow_dotted_names=True)  # This is bad!

    # Run the server's main loop
    server.serve_forever()