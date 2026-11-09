"""Preview/confirmation client for the fixed-scope privileged helper."""

import difflib
import hashlib
import json
from pathlib import Path
import subprocess
from .privileged import rules_valid, profile

HELPER = Path("/usr/lib/jaltrix/jaltrix/privileged.py")


def available():
    return (
        HELPER.is_file()
        and HELPER.stat().st_uid == 0
        and not HELPER.stat().st_mode & 0o022
    )


def prepare(action, reason, **parameters):
    if not reason.strip():
        raise ValueError("A justification is required")
    request = dict(action=action, reason=reason, approved=True, **parameters)
    if action in ("configure", "deploy_rules", "rollback"):
        files = {
            name: (Path("/etc/jaltrix") / name).read_text()
            for name in ("local.rules", "snort.lua", "sensor.env")
        }
        request["expected"] = hashlib.sha256(
            json.dumps(files, sort_keys=True).encode()
        ).hexdigest()
        if action == "configure":
            lua, env = profile(parameters["interface"], parameters["network"])
            request["preview"] = "".join(
                difflib.unified_diff(
                    (files["snort.lua"] + files["sensor.env"]).splitlines(True),
                    (lua + env).splitlines(True),
                    fromfile="current",
                    tofile="proposed",
                )
            )
        elif action == "deploy_rules":
            rules_valid(parameters["rules"])
            request["preview"] = "".join(
                difflib.unified_diff(
                    files["local.rules"].splitlines(True),
                    parameters["rules"].splitlines(True),
                    fromfile="current rules",
                    tofile="proposed rules",
                )
            )
        else:
            request["preview"] = (
                "Restore the previous managed profile; validate and restart only if currently active."
            )
    else:
        request["preview"] = json.dumps(parameters, indent=2)
    return request


def execute(request):
    if not available():
        raise RuntimeError("Installed administrator helper unavailable")
    result = subprocess.run(
        [
            "/usr/bin/pkexec",
            "--disable-internal-agent",
            "/usr/bin/python3",
            "-I",
            str(HELPER),
        ],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=180,
    )
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        raise RuntimeError("Administrator authorization cancelled or helper failed")
    if result.returncode:
        raise RuntimeError(payload.get("error", "Privileged operation failed"))
    return payload
