from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

HOST = "127.0.0.1"
PORT = 8080
TEST_PAGE = Path(__file__).with_name("test.html")


class LoginHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in {"/", "/test.html"}:
            html = TEST_PAGE.read_text(encoding="utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        self.send_error(404, "File not found")

    def do_POST(self):
        if self.path != "/login":
            self.send_error(404, "File not found")
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
        fields = parse_qs(body)

        username = fields.get("username", [""])[0]
        password = fields.get("password", [""])[0]

        print(f"[login_server] Received POST /login username={username} password={password}")

        response = """
<!DOCTYPE html>
<html lang=\"en\">
<head><meta charset=\"UTF-8\"><title>Submitted</title></head>
<body>
  <h2>Form submitted</h2>
  <p>Username: {username}</p>
  <p>Password: {password}</p>
  <p><a href=\"/test.html\">Back</a></p>
</body>
</html>
""".format(username=username, password=password)

        encoded = response.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


if __name__ == "__main__":
    print(f"[*] Login test server listening on http://{HOST}:{PORT}")
    server = HTTPServer((HOST, PORT), LoginHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("\n[*] Login test server stopped")
