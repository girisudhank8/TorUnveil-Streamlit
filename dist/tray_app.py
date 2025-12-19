import pystray
from pystray import MenuItem as item
from PIL import Image
import subprocess
import sys
import webbrowser
import threading
import time

streamlit_proc = None

def start_app()
    global streamlit_proc
    streamlit_proc = subprocess.Popen([
        sys.executable, -m, streamlit, run,
        app.py,
        --server.headless=true,
        --server.port=8501
    ])
    time.sleep(3)
    webbrowser.open(httplocalhost8501)

def stop_app(icon, item)
    if streamlit_proc
        streamlit_proc.terminate()
    icon.stop()

def open_ui(icon, item)
    webbrowser.open(httplocalhost8501)

def main()
    threading.Thread(target=start_app, daemon=True).start()
    image = Image.new(RGB, (64, 64), black)

    icon = pystray.Icon(
        TorUnveil,
        image,
        menu=pystray.Menu(
            item(Open UI, open_ui),
            item(Exit, stop_app)
        )
    )
    icon.run()

if __name__ == __main__
    main()
