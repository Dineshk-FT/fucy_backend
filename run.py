from app import create_app
from waitress import serve

app = create_app()

if __name__ == '__main__':
    serve(
        app,
        host='127.0.0.1',
        port=5001,
        channel_timeout=600,      # 10 minutes
        connection_limit=1000,
        cleanup_interval=30,
        recv_bytes=1024**2,       # 1MB
        send_bytes=1024**2,       # 1MB
        url_scheme='http'
    )