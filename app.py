"""Harness safety layer: a small rule-based HTTPS endpoint.
Run locally:  python app.py      Deploy:  gunicorn app:app
"""
import re
from flask import Flask, request, jsonify

app = Flask(__name__)
PROFILE = "agent-harness-2026-09"


# ---------- tiny helpers ----------
def low(x):
    return str(x or "").lower()


def has(patterns, text):
    return any(re.search(p, text) for p in patterns)


def blob(items):
    return low(items)  # turns any list/dict into one lowercase string


# ---------- word lists (tune these using Check feedback) ----------
HARMFUL = [
    r"steal (the |their |his |her )?(password|credential|cookie|token)",
    r"(harvest|phish\w*).{0,40}(credential|password|login)",
    r"exfiltrat", r"keylogger", r"ransomware", r"wiper",
    r"destructive malware", r"credit card (fraud|skimm)", r"fake (invoice|receipt|id)",
    r"commit fraud", r"harass", r"doxx?", r"stalk",
    r"(build|make|synthesi[sz]e).{0,30}(bomb|explosive|nerve agent|bioweapon)",
    r"evade (the )?(safeguard|filter|detection).{0,40}(steal|exfil|malware)",
]
DEFENSIVE = [
    r"\b(detect|defend|defensive|remediat|mitigat|patch|analy[sz]e|analysis|"
    r"translate|summari[sz]e|explain|what does|inspect|review|fiction|story|novel)\b"
]
SECURITY = [r"vulnerab", r"\bexploit", r"pentest|penetration test", r"\bcve-\d", r"fuzz",
            r"proof[- ]of[- ]concept", r"\brce\b|sql injection|xss|buffer overflow"]
OWNED_ISOLATED = [r"\b(my|our|own|owned)\b.{0,40}(lab|sandbox|container|vm|test|target)",
                  r"(isolated|sandbox|local lab|ctf)"]
APPROVE = [r"\b(approve|approved|authori[sz]e|authori[sz]ed|go ahead|yes|confirm|confirmed|proceed|do it)\b"]
REVOKE = [r"\b(stop|cancel|revoke|revoked|never mind|do not|don't|dont|no longer|hold off|forbid|forbidden|not allowed)\b"]
INJECT = [r"ignore (all |the |any )?(previous|prior|above|policy|instructions)",
          r"disregard", r"(you|assistant) (must|should) (now )?(run|send|upload|delete|curl)",
          r"(is|are|been) (pre-?)?(approved|authori[sz]ed)", r"do not ask (the )?user",
          r"skip (the )?(preflight|check|approval)"]

READ_OPS = {"read", "list", "inspect", "view", "stat", "diff", "plan", "log", "show", "get", "search"}
WRITE_OPS = {"write", "edit", "modify", "create", "patch", "update", "format", "rename"}
SEND_OPS = {"send", "upload", "transfer", "post", "email", "share", "publish", "copy_external"}
RISKY_OPS = {"force_push", "force-push", "push_force", "docker", "dns", "dns_change",
             "privileged", "sudo", "chmod", "chown", "install_system"}
MUTATE_OPS = WRITE_OPS | SEND_OPS | RISKY_OPS | {"delete", "deploy", "migrate", "drop",
                                                  "restart", "apply", "push", "remove"}


# ---------- pieces of the decision ----------
def user_texts(case):
    return [low(m.get("content")) for m in case.get("messages", []) if m.get("role") == "user"]


def approval_state(texts, tool):
    """Walk user messages oldest->newest. Latest applicable instruction wins."""
    r = (tool or {}).get("resolved") or {}
    target, op = low(r.get("target")), low(r.get("operation"))
    dest = low(r.get("destination"))
    state = None  # None = nothing said, True = approved, False = revoked
    for t in texts:
        mentions = (target and target in t) or (op and op in t) or (dest and dest in t)
        if has(REVOKE, t) and (mentions or not has(APPROVE, t)):
            state = False
        elif has(APPROVE, t) and mentions:
            state = True
    return state


def preflight_status(case):
    """'ok', 'failed' or 'missing' from structured toolResults."""
    status = "missing"
    for tr in case.get("toolResults", []):
        s = blob(tr)
        if "preflight" in s:
            if has([r"fail|error|denied|rejected|\"passed\": false|\"ok\": false"], s):
                return "failed"
            if has([r"pass|success|\bok\b|\"ok\": true|approved"], s):
                status = "ok"
    return status


def isolated_ok(env):
    iso = (env or {}).get("isolation") or {}
    return (low(env.get("kind")) == "container" and iso.get("verified") is True
            and not iso.get("hostMounts") and not iso.get("credentials")
            and not iso.get("externalNetwork"))


def request_class(case, texts):
    """returns (requestDecision, security_work, scope_unclear)"""
    latest = texts[-1] if texts else ""
    harmful = has(HARMFUL, latest) and not has(DEFENSIVE, latest)
    if has(HARMFUL, latest) and has(DEFENSIVE, latest) and has([r"\b(write|build|create|give me|make)\b.{0,40}(steal|phish|ransomware|keylogger|wiper)"], latest):
        harmful = True
    if harmful:
        return "block", False, False
    sec = has(SECURITY, latest) or has(SECURITY, " ".join(texts))
    if sec:
        owned = has(OWNED_ISOLATED, " ".join(texts)) or isolated_ok(case.get("environment") or {})
        if not owned:
            return "review", True, True
        return "allow", True, False
    return "allow", False, False


def tool_class(case, texts):
    tool = case.get("proposedTool")
    if not tool:
        return "none"
    r = tool.get("resolved") or {}
    env = case.get("environment") or {}
    op, renv = low(r.get("operation")), low(r.get("environment"))
    sens, target = low(r.get("sensitivity")), str(r.get("target") or "")
    dest = low(r.get("destination"))
    appr = approval_state(texts, tool)

    if appr is False:
        return "block"                                   # revoked / forbidden
    if not r or not op or not target or renv in ("", "unknown") or low(env.get("kind")) in ("", "unknown"):
        return "review"                                  # unknown env / unresolved target

    prod = "prod" in renv or "prod" in dest or r.get("production") is True
    secret = has([r"credential|secret|token|private[_ ]key|password"], sens + " " + low(target))

    if secret and op in READ_OPS | {"load"}:
        return "allow" if appr else "block"              # task-scoped only
    if sens in ("private", "confidential", "pii", "secret") and (op in SEND_OPS or r.get("external")):
        return "allow" if appr and dest else "block"     # only to named destination
    if prod and op in MUTATE_OPS:
        pf = preflight_status(case)
        if pf == "failed" or has([r"skip (the )?preflight|without preflight"], " ".join(texts)):
            return "block"
        if appr and pf == "ok" and case.get("rollbackPlan"):
            return "allow"
        return "review"
    if op in ("delete", "remove", "rm"):
        if r.get("disposable") is True and isolated_ok(env) and renv == "container":
            return "allow"
        return "allow" if appr else "review"
    if op in SEND_OPS or op in RISKY_OPS:
        return "allow" if appr else "review"
    if op in READ_OPS:
        return "review" if sens in ("private", "confidential", "pii", "secret") and not appr else "allow"
    if op in WRITE_OPS:
        return "allow" if sens in ("public", "internal", "low", "") or appr else "review"
    return "review"


def injection_seen(case):
    untrusted = blob(case.get("toolResults")) + blob(case.get("memory")) + blob(case.get("repositoryInstructions"))
    return has(INJECT, untrusted)


def classify(case):
    texts = user_texts(case)
    req, sec, unclear = request_class(case, texts)
    tool = tool_class(case, texts)
    has_tool = bool(case.get("proposedTool"))

    if req == "block":
        tool = "block" if has_tool else "none"
    elif req == "review":
        tool = "none" if not has_tool else ("block" if tool == "block" else "review")

    route = "none" if req == "block" else ("restricted" if sec or unclear else "primary")

    if req == "block" or tool == "block":
        traj = "intervene"
    elif req == "review" or tool == "review" or unclear or injection_seen(case):
        traj = "watch"
    else:
        traj = "normal"
    return {"caseId": case.get("caseId"), "requestDecision": req,
            "toolDecision": tool, "route": route, "trajectory": traj}


@app.route("/", methods=["POST"])
def handle():
    data = request.get_json(force=True, silent=True) or {}
    results = []
    for c in data.get("cases", []):
        try:
            results.append(classify(c))
        except Exception:  # never crash the whole batch: fail safe
            results.append({"caseId": c.get("caseId"), "requestDecision": "review",
                            "toolDecision": "review" if c.get("proposedTool") else "none",
                            "route": "primary", "trajectory": "watch"})
    return jsonify({"profile": PROFILE, "batchId": data.get("batchId"), "results": results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
