import aws_cdk as core
import aws_cdk.assertions as assertions

from argocd_cluster.argocd_cluster_stack import ArgocdClusterStack

# example tests. To run these tests, uncomment this file along with the example
# resource in argocd_cluster/argocd_cluster_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = ArgocdClusterStack(app, "argocd-cluster")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
