"""Render docs/architecture.png with official AWS icons.

    python3 diagram.py   (needs diagrams and Graphviz)

The runbook steps read left to right in execution order, containment first,
with each step's effect drawn beneath it.
"""

from diagrams import Cluster, Diagram, Edge
from diagrams.aws.compute import EC2, Lambda
from diagrams.aws.integration import SNS, Eventbridge
from diagrams.aws.security import IAM, KMS, Guardduty
from diagrams.aws.storage import EBS, S3

STEP = "#232f3e"
EFFECT = "#b03a2e"

with Diagram(
    "AWS Incident Response and Forensics Automation",
    filename="docs/architecture",
    outformat="png",
    show=False,
    direction="LR",
    graph_attr={"fontsize": "18", "bgcolor": "white", "pad": "0.4", "nodesep": "0.7", "ranksep": "0.8"},
    node_attr={"fontsize": "12"},
):
    guardduty = Guardduty("GuardDuty finding\nHigh or above")
    rule = Eventbridge("EventBridge rule")

    with Cluster("Step Functions runbook, in order"):
        isolate = Lambda("Isolate\nquarantine SG")
        snapshot = Lambda("Snapshot\nevery EBS volume")
        encrypt = Lambda("Re-encrypt\ncopies")
        revoke = Lambda("Revoke\nsessions")
        collect = Lambda("Collect\nmanifest")
        isolate >> Edge(color=STEP) >> snapshot >> Edge(color=STEP) >> encrypt >> Edge(color=STEP) >> revoke >> Edge(color=STEP) >> collect

    victim = EC2("Compromised instance\nno ingress, no egress")
    snaps = EBS("Source snapshots")
    cmk = KMS("Forensics CMK")
    role = IAM("Instance role\ndeny tokens issued before now")
    bucket = S3("Evidence bucket\nSSE-KMS")
    notify = SNS("[CONTAINED] or\n[FAILED] notice")

    guardduty >> rule >> isolate
    isolate >> Edge(color=EFFECT) >> victim
    snapshot >> Edge(color=EFFECT) >> snaps
    encrypt >> Edge(color=EFFECT) >> cmk
    revoke >> Edge(color=EFFECT) >> role
    collect >> Edge(color=EFFECT) >> bucket
    collect >> notify
