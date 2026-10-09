import http.server
import socketserver
import webbrowser
import os
import sys

PORT = 3000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIRECTORY = os.path.join(BASE_DIR, "dist") if os.path.exists(os.path.join(BASE_DIR, "dist")) else BASE_DIR

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()

if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    url = f"http://localhost:{PORT}"
    print("=" * 55)
    print(f"🚀 绪山真寻 HRT Tracker (含新版舌下) 本地服务已启动！")
    print(f"👉 本地访问地址: {url}")
    print(f"📁 静态资源目录: {DIRECTORY}")
    print("按 Ctrl+C 可停止本地服务")
    print("=" * 55)
    sys.stdout.flush()

    try:
        webbrowser.open(url)
    except Exception:
        pass

    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n服务已停止。")
