from diagrams import Diagram, Cluster, Edge
from diagrams.aws.security import Guardduty, IAM, KMS
from diagrams.aws.compute import EC2, Lambda
from diagrams.aws.integration import Eventbridge, StepFunctions, SNS
from diagrams.aws.storage import S3, EBS

graph_attrs = {
    "fontsize": "13",
    "bgcolor": "white",
    "pad": "0.5",
    "splines": "ortho",
}

node_attrs = {
    "fontsize": "11",
}

with Diagram(
    "AWS Incident Response and Forensics Automation",
    filename="docs/architecture",
    outformat="png",
    show=False,
    direction="LR",
    graph_attr=graph_attrs,
    node_attr=node_attrs,
):
    victim = EC2("compromised\ninstance")
    guardduty = Guardduty("GuardDuty\nfinding (>= High)")
    rule = Eventbridge("EventBridge\nrule")

    with Cluster("Step Functions runbook"):
        isolate = Lambda("isolate\n(quarantine SG)")
        snapshot = Lambda("snapshot\nEBS volumes")
        encrypt = Lambda("re-encrypt\ncopies")
        revoke = Lambda("revoke\nsessions")
        collect = Lambda("collect\nevidence")

    sfn = StepFunctions("state machine")

    cmk = KMS("forensics CMK")
    evidence = S3("evidence bucket\n(SSE-KMS)")
    role = IAM("instance role\n(deny old sessions)")
    sns = SNS("responder\nnotification")

    victim >> Edge(label="behavioral\nthreat") >> guardduty >> rule >> sfn
    sfn >> Edge(color="firebrick") >> isolate >> Edge(label="contain") >> victim
    sfn >> snapshot >> Edge(label="capture") >> EBS("volume\nsnapshots")
    snapshot >> encrypt >> Edge(label="re-encrypt", color="darkgreen") >> cmk
    encrypt >> evidence
    sfn >> revoke >> Edge(label="invalidate", color="firebrick") >> role
    sfn >> collect >> Edge(label="manifest") >> evidence
    sfn >> Edge(style="dashed") >> sns
