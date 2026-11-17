"""Local WSGI launcher with visible startup feedback."""
import argparse
import sys
import webbrowser
from waitress import create_server
from app import app, monitor

def port_number(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("Port must be between 1 and 65535")
    return port

def main():
    parser = argparse.ArgumentParser(description="Start the Sentryline local analyst workspace")
    parser.add_argument("--port", type=port_number, default=5000)
    parser.add_argument("--open", action="store_true", help="Open the app in your default browser")
    args = parser.parse_args()
    try:
        server = create_server(app, host="127.0.0.1", port=args.port, threads=4)
    except OSError as exc:
        print(f"Could not start on port {args.port}: {exc}", file=sys.stderr, flush=True)
        print("Stop the existing server with Ctrl+C, or run: python serve.py --port 5001", file=sys.stderr)
        return 1
    url = f"http://127.0.0.1:{server.effective_port}"
    print(f"\nSentryline is running at {url}", flush=True)
    print("Keep this terminal open. Press Ctrl+C to stop.\n", flush=True)
    if args.open:
        webbrowser.open(url)
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nSentryline stopped.", flush=True)
    finally:
        monitor.stop()
        server.close()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
