#!/usr/bin/env python3
import os
import aws_cdk as cdk
from _stacks.argocd_cluster_stack import ArgocdClusterStack


env = cdk.Environment(
    account=os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]),
    region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"]),
)

app = cdk.App()
ArgocdClusterStack(app, "ArgocdClusterStack", env=env)

app.synth()
