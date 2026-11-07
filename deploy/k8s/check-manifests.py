#!/usr/bin/env python3
"""Semantic checks on rendered Token Vault manifests (things schema validation does not catch).

    kustomize build deploy/k8s/overlays/local | python3 deploy/k8s/check-manifests.py

Checks: selectors select something; NetworkPolicy peers exist; every referenced Secret exists
(or is produced by an ExternalSecret); each Secret holds only its own service's keys; pods in
restricted namespaces meet the Pod Security "restricted" profile (numeric non-root user, no
privilege escalation, all capabilities dropped, seccomp) and use read-only root filesystems;
Ingress backends exist; images are pinned. Exits 1 with the list of problems.
"""
import base64
import sys

import yaml

docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
problems = []

def ns_of(d):
    return d["metadata"].get("namespace", "default")

def matches(selector, labels):
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())

workloads = [d for d in docs if d["kind"] in ("Deployment", "StatefulSet")]
pods = [(ns_of(w), w["spec"]["template"]["metadata"].get("labels", {}), w) for w in workloads]
namespaces = {d["metadata"]["name"]: d["metadata"].get("labels", {}) for d in docs if d["kind"] == "Namespace"}
secrets = {(ns_of(d), d["metadata"]["name"]): d for d in docs if d["kind"] == "Secret"}
external = {(ns_of(d), d["spec"]["target"]["name"]) for d in docs if d["kind"] == "ExternalSecret"}
services = {(ns_of(d), d["metadata"]["name"]): d for d in docs if d["kind"] == "Service"}

def selects_pod(ns, selector):
    return any(p_ns == ns and matches(selector, labels) for p_ns, labels, _ in pods)

# Selectors
for w in workloads:
    name = f'{w["kind"]} {ns_of(w)}/{w["metadata"]["name"]}'
    sel = w["spec"]["selector"].get("matchLabels", {})
    if not matches(sel, w["spec"]["template"]["metadata"].get("labels", {})):
        problems.append(f"{name}: selector does not match its own pod template")
for d in docs:
    kind, name = d["kind"], f'{d["kind"]} {ns_of(d)}/{d["metadata"]["name"]}'
    if kind == "Service" and not selects_pod(ns_of(d), d["spec"].get("selector", {})):
        problems.append(f"{name}: selects no pods")
    if kind == "PodDisruptionBudget" and not selects_pod(ns_of(d), d["spec"].get("selector", {}).get("matchLabels", {})):
        problems.append(f"{name}: selects no pods")
    if kind == "NetworkPolicy":
        own = d["spec"]["podSelector"].get("matchLabels", {})
        if own and not selects_pod(ns_of(d), own):
            problems.append(f"{name}: podSelector selects no pods")
        for direction in ("ingress", "egress"):
            for rule in d["spec"].get(direction) or []:
                for peer in rule.get("from" if direction == "ingress" else "to", []):
                    peer_ns = (peer.get("namespaceSelector") or {}).get("matchLabels", {}).get("kubernetes.io/metadata.name")
                    labels = (peer.get("podSelector") or {}).get("matchLabels", {})
                    if peer_ns == "ingress-nginx" or labels.get("k8s-app") == "kube-dns":
                        continue  # outside Token Vault
                    target_ns = peer_ns or ns_of(d)
                    if labels and not selects_pod(target_ns, labels):
                        problems.append(f"{name}: {direction} peer {labels} in {target_ns} matches no pods")

# Secrets: references exist, and each holds only its own keys
OWN_KEYS = {"VAULT_ENCRYPTION_KEY": "token-vault-customer", "VAULT_PREVIOUS_ENCRYPTION_KEYS": "token-vault-customer", "CMS_SIGNING_PRIVATE_KEY": "token-vault/token-vault-cms-api"}
for ns, _labels, w in pods:
    for c in w["spec"]["template"]["spec"]["containers"]:
        for ref in c.get("envFrom", []):
            sname = ref.get("secretRef", {}).get("name")
            if sname and (ns, sname) not in secrets and (ns, sname) not in external:
                problems.append(f'{w["metadata"]["name"]}: Secret {ns}/{sname} is neither defined nor produced by an ExternalSecret')
for (ns, sname), s in secrets.items():
    for key in (s.get("data") or {}) | (s.get("stringData") or {}):
        owner = OWN_KEYS.get(key)
        if owner and owner not in (ns, f"{ns}/{sname}"):
            problems.append(f"Secret {ns}/{sname}: holds {key}, which belongs only to {owner}")
    for key, value in (s.get("data") or {}).items():
        if key.endswith("_URL") and "@" in base64.b64decode(value).decode():
            host = base64.b64decode(value).decode().split("@", 1)[1].split("/", 1)[0]
            if not host:
                problems.append(f"Secret {ns}/{sname}: {key} has no host")

# Pod security
for ns, _labels, w in pods:
    if namespaces.get(ns, {}).get("pod-security.kubernetes.io/enforce") != "restricted":
        continue
    spec, name = w["spec"]["template"]["spec"], f'{ns}/{w["metadata"]["name"]}'
    psc = spec.get("securityContext", {})
    if not psc.get("runAsNonRoot") or not isinstance(psc.get("runAsUser"), int) or psc.get("runAsUser") == 0:
        problems.append(f"{name}: needs runAsNonRoot with a numeric non-zero runAsUser")
    if psc.get("seccompProfile", {}).get("type") != "RuntimeDefault":
        problems.append(f"{name}: needs seccompProfile RuntimeDefault")
    for c in spec["containers"]:
        csc = c.get("securityContext", {})
        if csc.get("allowPrivilegeEscalation") is not False:
            problems.append(f"{name}/{c['name']}: allowPrivilegeEscalation must be false")
        if csc.get("capabilities", {}).get("drop") != ["ALL"]:
            problems.append(f"{name}/{c['name']}: must drop ALL capabilities")
        if csc.get("readOnlyRootFilesystem") is not True:
            problems.append(f"{name}/{c['name']}: root filesystem must be read-only")
        if ":" not in c["image"] or c["image"].endswith(":latest"):
            problems.append(f"{name}/{c['name']}: image {c['image']} is not pinned")

# Ingress backends
for d in docs:
    if d["kind"] != "Ingress":
        continue
    for rule in d["spec"].get("rules", []):
        for path in rule["http"]["paths"]:
            svc = path["backend"]["service"]
            target = services.get((ns_of(d), svc["name"]))
            if not target:
                problems.append(f'Ingress {d["metadata"]["name"]}: no Service {svc["name"]}')
            elif svc["port"].get("name") and svc["port"]["name"] not in [p.get("name") for p in target["spec"]["ports"]]:
                problems.append(f'Ingress {d["metadata"]["name"]}: Service {svc["name"]} has no port {svc["port"]["name"]}')

if problems:
    print("\n".join(f"FAIL {p}" for p in problems))
    sys.exit(1)
print(f"ok: {len(docs)} resources, {len(workloads)} workloads checked")
