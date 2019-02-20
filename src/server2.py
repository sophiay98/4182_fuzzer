#!/usr/bin/env python
# Reflects the requests from HTTP methods GET, POST, PUT, and DELETE
# Written by Nathan Hamiel (2010)

from http.server import HTTPServer, BaseHTTPRequestHandler
from optparse import OptionParser


class RequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        path = self.path

        print("\n-------- GET Start --------\n")
        print("path: " + path)
        print(self.headers)
        print("\n-------- GET End   --------\n")

        self.send_response(200)
        self.send_header("Set-Cookie", "foo=bar")

    def do_POST(self):
        path = self.path

        print("\n-------- POST Start -------\n")

        print("path: " + path)
        request_headers = self.headers
        content_length = request_headers.getheaders('content-length')
        length = int(content_length[0]) if content_length else 0

        print(request_headers)
        print(self.rfile.read(length))
        print("\n-------- POST End  -------\n")

        self.send_response(200)

    do_PUT = do_POST
    do_DELETE = do_GET


if __name__ == "__main__":
    parser = OptionParser()
    parser.usage = ("Creates an http-server that will echo out any GET or POST parameters\n"
                    "Run:\n\n"
                    "   reflect")
    (options, args) = parser.parse_args()

    port = 1338
    print("Server open on localhost: " + str(port))
    server = HTTPServer(('', port), RequestHandler)
    server.serve_forever()
