from app import create_app, socketio

app = create_app()

if __name__ == "__main__":
    print(">>> STARTING RL BACKEND SERVER <<<")
    print(">>> Open auth pages at http://127.0.0.1:5000/auth/login (use 127.0.0.1 if localhost fails) <<<")
    # use_reloader=False: Werkzeug's reloader forks a child; HTTP (Burp) and Socket.IO
    # (dashboard) can hit different processes so live logs never appear.
    socketio.run(
        app,
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )
