#!/usr/bin/env python3
"""Local OpenSSH interoperability checks; uses temporary keys and loopback only.

Run against a default build and again with DROPBEAR_SVR_PUBKEY_OPTIONS=0:
  python3 test/cert_auth_regressions.py --dropbear ./dropbear --dbclient ./dbclient
  python3 test/cert_auth_regressions.py --dropbear ./dropbear --reject-certificates
"""

import argparse
import os
from pathlib import Path
import pwd
import socket
import subprocess
import tempfile
import time


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, timeout=20, **kwargs)


def require(result, success, label):
    if (result.returncode == 0) != success:
        raise AssertionError(f"{label}: exit {result.returncode}\n"
                             f"{result.stdout}\n{result.stderr}")
    print(f"PASS: {label}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dropbear", required=True, type=Path)
    parser.add_argument("--dbclient", type=Path)
    parser.add_argument("--dropbearkey", type=Path,
                        default=Path(__file__).resolve().parents[1] / "dropbearkey")
    parser.add_argument("--reject-certificates", action="store_true")
    args = parser.parse_args()
    server = str(args.dropbear.resolve())
    client = str(args.dbclient.resolve()) if args.dbclient else None
    username = pwd.getpwuid(os.getuid()).pw_name

    with tempfile.TemporaryDirectory(prefix="dropbear-cert-test-") as tmp:
        work = Path(tmp)
        keys = work / "keys"
        keys.mkdir(mode=0o700)
        require(run([str(args.dropbearkey.resolve()), "-t", "ed25519",
                     "-f", str(work / "host")]), True, "generate host")
        for name, kind in (("ca", "ed25519"),
                           ("user", "ed25519"), ("rsa", "rsa")):
            cmd = ["ssh-keygen", "-q", "-t", kind, "-N", "", "-f", str(work / name)]
            if kind == "rsa":
                cmd.extend(["-b", "2048"])
            require(run(cmd), True, f"generate {name}")

        def sign(*options):
            require(run(["ssh-keygen", "-q", "-s", str(work / "ca"),
                         "-I", "regression", "-n", username, *options,
                         str(work / "user.pub")]), True, "sign certificate")

        sign("-O", "clear")
        authfile = keys / "authorized_keys"
        ca_line = "cert-authority " + (work / "ca.pub").read_text()
        authfile.write_text(ca_line)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        with (work / "server.log").open("w+") as log:
            proc = subprocess.Popen([server, "-F", "-E", "-s", "-r", str(work / "host"),
                                     "-p", f"127.0.0.1:{port}", "-P", str(work / "pid"),
                                     "-D", "keys"], cwd=work, stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if proc.poll() is not None:
                        raise AssertionError("server exited during startup")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise AssertionError("server startup timed out")

                base = ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes",
                        "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                        "-p", str(port), "-i", str(work / "user")]

                def ssh(*opts, command="echo CERT_OK"):
                    return run([*base, *opts, f"{username}@127.0.0.1", command])

                require(ssh(), not args.reject_certificates,
                        "restricted certificate authentication")
                require(ssh("-o", "ExitOnForwardFailure=yes", "-R",
                            "127.0.0.1:0:127.0.0.1:9"), False,
                        "certificate without permit-port-forwarding cannot forward")
                if args.reject_certificates:
                    sign()
                    authfile.write_text('command="echo FORCED_OK",' + ca_line)
                    require(ssh(), False, "CA-line restrictions require options support")
                if not args.reject_certificates:
                    sign("-O", "force-command=echo FORCED_OK")
                    result = ssh(command="echo SHOULD_NOT_RUN")
                    require(result, True, "forced command authentication")
                    assert result.stdout.strip() == "FORCED_OK", result.stdout
                    authfile.write_text('command="echo DIFFERENT",' + ca_line)
                    require(ssh(), False, "conflicting CA and certificate commands rejected")
                    sign()
                    authfile.write_text('command="echo CA_FORCED_OK",' + ca_line)
                    result = ssh(command="echo SHOULD_NOT_RUN")
                    require(result, True, "CA-line forced command authentication")
                    assert result.stdout.strip() == "CA_FORCED_OK", result.stdout
                    authfile.write_text(ca_line)
                    sign("-O", "critical:unsupported-regression-option")
                    require(ssh(), False, "unknown critical option rejected")

                # A certificate-disabled build must retain ordinary key auth.
                (work / "user-cert.pub").unlink()
                authfile.write_text((work / "user.pub").read_text())
                require(ssh(), True, "ordinary public-key authentication")

                if client:
                    authfile.write_text((work / "rsa.pub").read_text())
                    agent_sock = str(work / "agent.sock")
                    env = dict(os.environ, SSH_AUTH_SOCK=agent_sock)
                    agent = subprocess.Popen(["ssh-agent", "-D", "-a", agent_sock],
                                             stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL)
                    try:
                        for _ in range(100):
                            if Path(agent_sock).exists():
                                break
                            if agent.poll() is not None:
                                raise AssertionError("ssh-agent exited")
                            time.sleep(0.05)
                        require(run(["ssh-add", str(work / "rsa")], env=env),
                                True, "load RSA agent key")
                        require(run([client, "-y", "-y", "-T", "-p", str(port),
                                     f"{username}@127.0.0.1", "echo AGENT_OK"], env=env),
                                True, "RSA agent authentication")
                    finally:
                        agent.terminate()
                        agent.wait(timeout=5)
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read())
                raise
            finally:
                proc.terminate()
                proc.wait(timeout=5)


if __name__ == "__main__":
    main()
