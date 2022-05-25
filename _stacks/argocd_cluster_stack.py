import json
import yaml
from passlib.context import CryptContext
import aws_cdk
from aws_cdk import Stack
from constructs import Construct
from aws_cdk import aws_ec2
from aws_cdk import aws_iam
from aws_cdk import aws_eks
import boto3


class ArgocdClusterStack(Stack):

    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 env: aws_cdk.Environment,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.configure = {
            # VPC
            'vpc_name': 'argocd',
            'vpc_cidr': '10.11.0.0/16',
            # Addon - Argocd
            'cluster_name': 'argocd',
            'argocd_namespace_name': 'argocd',
            # 'argocd_chart_version': '4.6.0',
            'argocd_release': 'argocd-addon',
            'argocd_repository': 'https://argoproj.github.io/argo-helm',
            'asm_argo_server_pw': '/argocd/server/admin/password',

            # Domain & Cert
            'domain': 'yamazon.tk',
            'sub_domain': 'argocd.yamazon.tk',
            'cert_arn': ('arn:aws:acm:ap-northeast-1:338456725408'
                         ':certificate/124163b3-7ec8-4cf7-af6e-f05d8bc6ce8f'),
            'secret_name': 'ArgocdServerAdminPassword',
        }

        self.resources = {
            # 'vpc': None,
            # 'cluster': None,
        }

        self.create_vpc()
        # VPC - three tier, 2az

        self.create_eks()
        # Create EKS Cluster
        #   With
        #       AWS LoadBalancer Controller
        #       External DNS
        #       Fluentbit
        #       CloudWatch Agent

        self.deploy_argocd()
        # helmが動作しなければ手動で実施
        # % kubectl create namespace argocd
        #
        # % kubectl apply -n argocd -f manifests/argocd-install.yaml
        # または kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

        self.add_alb_ingress_to_argocd()
        # ALBが動作するまで10分程度かかることもある。

    def create_vpc(self):
        # --------------------------------------------------------------
        # VPC
        #   Three Tire Network
        # --------------------------------------------------------------
        self.resources['vpc'] = aws_ec2.Vpc(
            self,
            'Vpc',
            vpc_name=self.configure.get('vpc_name'),
            cidr=self.configure.get('vpc_cidr'),
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                aws_ec2.SubnetConfiguration(
                    name="Front",
                    subnet_type=aws_ec2.SubnetType.PUBLIC,
                    cidr_mask=24),
                aws_ec2.SubnetConfiguration(
                    name="Application",
                    subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_NAT,
                    cidr_mask=24),
                # aws_ec2.SubnetConfiguration(
                #     name="DataStore",
                #     subnet_type=aws_ec2.SubnetType.PRIVATE_ISOLATED,
                #     cidr_mask=24),
            ]
        )
        return

    def create_eks(self):
        # --------------------------------------------------------------
        # EKS Cluster
        #   Owner role for EKS Cluster
        # --------------------------------------------------------------
        _owner_role = aws_iam.Role(
            scope=self,
            id='EksClusterOwnerRole',
            role_name='ArgocdClusterOwnerRole',
            assumed_by=aws_iam.AccountRootPrincipal()
        )
        self.resources['cluster'] = aws_eks.Cluster(
            self,
            'EksAppCluster',
            cluster_name=self.configure.get('cluster_name'),
            version=aws_eks.KubernetesVersion.V1_21,
            default_capacity_type=aws_eks.DefaultCapacityType.NODEGROUP,
            default_capacity=1,
            # default_capacity_instance=aws_ec2.InstanceType('t3.small'),
            default_capacity_instance=aws_ec2.InstanceType('t3.medium'),
            vpc=self.resources.get('vpc'),
            masters_role=_owner_role
        )
        # CI/CDでClusterを作成する際、IAM Userでkubectlを実行する際に追加する。
        # kubectl commandを実行できるIAM Userを追加
        # _cluster.aws_auth.add_user_mapping(
        #         user=aws_iam.User.from_user_name(
        #                 self, 'K8SUser-yagitatakashi', 'yagitatakashi'),
        #         groups=['system:masters']
        # )

        # ----------------------------------------------------------
        # AWS LoadBalancer Controllerをインストールする
        # IngressからALBを作成する。
        # ----------------------------------------------------------
        self.deploy_aws_load_balancer_controller()

        # ----------------------------------------------------------
        # ExternalDNS
        # ExternalDNSは TLS証明書持つALBのレコードをR53に登録する
        # ----------------------------------------------------------
        self.deploy_external_dns()

        # ----------------------------------------------------------
        # Cloudwatch Container Insights - Metrics / CloudWatch Agent
        # ----------------------------------------------------------
        self.deploy_cloudwatch_container_insights_metrics()

        # ----------------------------------------------------------
        # Cloudwatch Container Insights - Logs / fluentbit
        # ----------------------------------------------------------
        self.deploy_cloudwatch_container_insights_logs()

        return

    def deploy_aws_load_balancer_controller(self):
        # ----------------------------------------------------------
        # AWS LoadBalancer Controller for AWS ALB
        #   - Service Account
        #   - Namespace: kube-system
        #   - Deployment
        #   - Service
        # ----------------------------------------------------------
        _cluster = self.resources.get('cluster')
        awslbcontroller_sa = _cluster.add_service_account(
            'LBControllerServiceAccount',
            name='aws-load-balancer-controller',  # fixed name
            namespace='kube-system',
        )

        statements = []
        with open('./policies/awslbcontroller-policy.json') as f:
            data = json.load(f)
            for statement in data['Statement']:
                statements.append(aws_iam.PolicyStatement.from_json(statement))

        policy = aws_iam.Policy(
            self, 'AWSLoadBalancerControllerIAMPolicy', statements=statements)
        policy.attach_to_role(awslbcontroller_sa.role)

        aws_lb_controller_chart = _cluster.add_helm_chart(
            'AwsLoadBalancerController',
            chart='aws-load-balancer-controller',
            release='aws-load-balancer-controller',  # Deploymentの名前になる。
            repository='https://aws.github.io/eks-charts',
            namespace='kube-system',
            create_namespace=False,  # 追加
            values={
                'clusterName': _cluster.cluster_name,
                'region': self.region,
                'vpc': self.configure.get('vpc'),
                'serviceAccount': {
                    'name': awslbcontroller_sa.service_account_name,
                    'create': False,
                    'annotations': {
                        'eks.amazonaws.com/role-arn': awslbcontroller_sa.role.role_arn
                    }
                }
            }
        )
        aws_lb_controller_chart.node.add_dependency(awslbcontroller_sa)

    def deploy_external_dns(self):
        # External DNS Controller
        #
        # External DNS Controller sets A-Record in the Hosted Zone of Route 53.
        #
        # how to use:
        #   Set DomainName in annotations of Ingress Manifest.
        #   ex.
        #       external-dns.alpha.kubernetes.io/hostname: DOMAIN_NAME
        # see more info
        #   ('https://aws.amazon.com/jp/premiumsupport/'
        #    'knowledge-center/eks-set-up-externaldns/')

        _cluster = self.resources.get('cluster')
        external_dns_service_account = _cluster.add_service_account(
            'external-dns',
            name='external-dns',
            namespace='kube-system'
        )
        external_dns_policy_statement_json_1 = {
            'Effect': 'Allow',
            'Action': [
                'route53:ChangeResourceRecordSets'
            ],
            'Resource': [
                'arn:aws:route53:::hostedzone/*'
            ]
        }

        external_dns_policy_statement_json_2 = {
            'Effect': 'Allow',
            'Action': [
                'route53:ListHostedZones',
                'route53:ListResourceRecordSets'
            ],
            'Resource': ["*"]
        }

        external_dns_service_account.add_to_principal_policy(
            aws_iam.PolicyStatement.from_json(
                external_dns_policy_statement_json_1)
        )
        external_dns_service_account.add_to_principal_policy(
            aws_iam.PolicyStatement.from_json(
                external_dns_policy_statement_json_2)
        )

        external_dns_chart = _cluster.add_helm_chart(
            'external-dns"',
            chart='external-dns',
            version='1.7.1',  # change to '1.9.0'
            release='externaldns',
            repository='https://kubernetes-sigs.github.io/external-dns/',
            namespace='kube-system',
            values={
                'serviceAccount': {
                    'name': external_dns_service_account.service_account_name,
                    'create': False,
                },
                # 'resources': {
                #     'requests': {
                #         'cpu': '0.25',
                #         'memory': '0.5Gi'
                #     }
                # }
            }

        )
        external_dns_chart.node.add_dependency(external_dns_service_account)

    def deploy_cloudwatch_container_insights_metrics(self):
        # CloudWatch Agent
        # namespace: amazon-cloudwatch -> kube-system
        # See more info 'https://docs.aws.amazon.com/AmazonCloudWatch/latest'
        #               'monitoring/Container-Insights-setup-metrics.html'

        _cluster: aws_eks.Cluster = self.resources.get('cluster')

        # Create the Service Account
        cloudwatch_container_insight_sa: aws_iam.Role = \
            _cluster.add_service_account(
                id='cloudwatch-agent',
                name='cloudwatch-agent',
                namespace='kube-system',
            )

        cloudwatch_container_insight_sa.role.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                'CloudWatchAgentServerPolicy')
        )

        # ----------------------------------------------------------
        # CloudWatch ConfigMap Setting
        # ----------------------------------------------------------
        cwagentconfig_json = {
            'agent': {
                'region': self.region
            },
            'logs': {
                'metrics_collected': {
                    'kubernetes': {
                        'cluster_name': _cluster.cluster_name,
                        'metrics_collection_interval': 60
                    }
                },
                'force_flush_interval': 5,
                'endpoint_override': f'logs.{self.region}.amazonaws.com'
            },
            'metrics': {
                'metrics_collected': {
                    'statsd': {
                        'service_address': ':8125'
                    }
                }
            }
        }
        cw_agent_configmap = {
            'apiVersion': 'v1',
            'kind': 'ConfigMap',
            'metadata': {
                'name': 'cwagentconfig',
                'namespace': 'kube-system'
            },
            'data': {
                'cwagentconfig.json': json.dumps(cwagentconfig_json)
            }
        }
        _cluster.add_manifest('CloudwatchContainerInsightConfigMap',
                              cw_agent_configmap)

        # ----------------------------------------------------------
        # Apply multiple yaml documents. - cloudwatch-agent.yaml
        # ----------------------------------------------------------
        with open('./manifests/cloudwatch-agent.yaml', 'r') as f:
            _yaml_docs = list(yaml.load_all(f, Loader=yaml.FullLoader))
        for i, _yaml_doc in enumerate(_yaml_docs, 1):
            _cluster.add_manifest(f'CWAgent{i}', _yaml_doc)

    def deploy_cloudwatch_container_insights_logs(self):
        # --------------------------------------------------------------
        # Cloudwatch Logs - fluent bit
        #   Namespace
        #   Service Account
        #   Deployment
        #   Service
        # https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-logs-FluentBit.html
        # 1. namespace: amazon-cloudwatchを作成
        # 2. Service Account作成
        # --------------------------------------------------------------

        _cluster = self.resources.get('cluster')
        # namespace: amazon-cloudwatch
        cloudwatch_namespace_name = 'amazon-cloudwatch'
        cloudwatch_namespace_manifest = {
            'apiVersion': 'v1',
            'kind': 'Namespace',
            'metadata': {
                'name': cloudwatch_namespace_name,
                'labels': {
                    'name': cloudwatch_namespace_name
                }
            }
        }
        cloudwatch_namespace = _cluster.add_manifest(
                  'CloudWatchNamespace', cloudwatch_namespace_manifest)

        # Service Account for fluent bit
        fluentbit_service_account = _cluster.add_service_account(
            'FluentbitServiceAccount',
            name='cloudwatch-sa',
            namespace=cloudwatch_namespace_name
        )
        fluentbit_service_account.node.add_dependency(cloudwatch_namespace)
        # FluentBitの場合は以下のPolicyを使う。kinesisなどを使う場合はPolicyは異なる
        fluentbit_service_account.role.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                'CloudWatchAgentServerPolicy')
        )
        # logsの保持期間(logRetentionDays)の変更ポリシーを追加
        logs_retention_policy = {
            'Effect': 'Allow',
            'Action': [
                'logs:PutRetentionPolicy'
            ],
            'Resource': ["*"]
        }
        fluentbit_service_account.role.add_to_principal_policy(
            aws_iam.PolicyStatement.from_json(logs_retention_policy)
        )

        # aws-for-fluent-bit DaemonSetのデプロイ
        cloudwatch_helm_chart = _cluster.add_helm_chart(
            'FluentBitHelmChart',
            namespace=cloudwatch_namespace_name,
            repository='https://aws.github.io/eks-charts',
            chart='aws-for-fluent-bit',
            release='aws-for-fluent-bit',
            version='0.1.16',
            values={
                'serviceAccount': {
                    'name': fluentbit_service_account.service_account_name,
                    'create': False
                },
                'cloudWatch': {
                    'enabled': True,
                    'match': "*",
                    'region': self.region,
                    'logGroupName': f'/aws/eks/fluentbit-cloudwatch/logs/{_cluster.cluster_name}/application',
                    # 'logGroupName': "/aws/eks/fluentbit-cloudwatch/logs/\$(kubernetes['namespace_name'])/\$(kubernetes['container_name']",
                    # 'logGroupName': "/aws/eks/fluentbit/logs/$(kubernetes['namespace_name'])/$(kubernetes['container_name']",
                    'logStreamPrefix': 'log-',  # 'fluent-bit-'
                    'logRetentionDays': 7,
                    'autoCreateGroup': True,
                },
                'kinesis': {'enabled': False},
                'elasticsearch': {'enabled': False},
                'firehose': {'enabled': False},
            }
        )
        cloudwatch_helm_chart.node.add_dependency(fluentbit_service_account)

    def deploy_argocd(self):
        # ----------------------------------------------------------------
        # Argo CD
        # namespace(argocd)とServiceAccountはHelm(argo-cd)で作成するため
        # ここでは作成しない。
        # ----------------------------------------------------------------
        _cluster = self.resources.get('cluster')
        _cert_arn = self.configure.get('cert_arn')
        _sub_domain = self.configure.get('sub_domain')

        # ----------------------------------------------------------------
        # Argo CD
        # ----------------------------------------------------------------
        _argocd_helm_chart = _cluster.add_helm_chart(
            'ArgocdHelmChart',
            namespace='argocd',
            repository=self.configure.get('argocd_repository'),
            chart='argo-cd',
            release='argocd',  # Ingressの指定があるので'argocd'に固定する。
            # version=self.configure.get('argocd_chart_version'),  # latest version
            values={
                'configs': {
                    'secret': {
                        'argocdServerAdminPassword': self.get_argocd_admin_password()
                    }
                }
            }
        )

    def get_argocd_admin_password(self):
        # ------------------------------------------------------
        # ASM Secret - argocdServerAdminPassword
        # configs.secret.argocdServerAdminPassword must be
        # Bcrypt hashed password.
        # https://artifacthub.io/packages/helm/argo/argo-cd
        # ------------------------------------------------------
        _secret_name = self.configure.get('secret_name')
        secret_string = self.get_asm_value_by_sdk(_secret_name)
        pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
        bcrypt_hashed = pwd_context.hash(secret_string)
        return bcrypt_hashed

    @staticmethod
    def get_asm_value_by_sdk(secret_name: str):
        # hash変換しなければならないのでCDKでのASM動的参照は使えない
        # AWS SDKで実際に値を取得する必要がある
        client = boto3.client('secretsmanager')
        secret_value = client.get_secret_value(SecretId=secret_name)
        secret_string = secret_value['SecretString']
        return secret_string

    def add_alb_ingress_to_argocd(self):  # new at 2022.05.24 16:30
        _cluster = self.resources.get('cluster')
        _namespace = self.configure.get('argocd_namespace_name')
        _cert_arn = self.configure.get('cert_arn')
        _sub_domain = self.configure.get('sub_domain')

        ingress_argocd_server_manifest = {
            'apiVersion': 'networking.k8s.io/v1',
            'kind': 'Ingress',
            'metadata': {
                'name': 'argocd',
                'namespace': 'argocd',
                'labels': {
                    'app.kubernetes.io/name': 'argocd-server'
                },
                'annotations': {
                    'kubernetes.io/ingress.class': 'alb',
                    'alb.ingress.kubernetes.io/scheme': 'internet-facing',
                    'alb.ingress.kubernetes.io/target-type': 'ip',
                    'alb.ingress.kubernetes.io/listen-ports': '[{"HTTPS":443}, {"HTTP":80}]',
                    'alb.ingress.kubernetes.io/healthcheck-path': '/healthz',
                    'alb.ingress.kubernetes.io/healthcheck-protocol': 'HTTPS',
                    'alb.ingress.kubernetes.io/backend-protocol': 'HTTPS',
                    'alb.ingress.kubernetes.io/actions.ssl-redirect': '{"Type": "redirect", "RedirectConfig": { "Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301"}}',
                    'alb.ingress.kubernetes.io/certificate-arn': _cert_arn,
                    'external-dns.alpha.kubernetes.io/hostname': _sub_domain,
                },
            },
            'spec': {
                'rules': [
                    {
                        'host': _sub_domain,
                        'http': {
                            'paths': [
                                {
                                    'backend': {
                                        'service': {
                                            'name': 'argocd-server',
                                            'port': {
                                                'number': 80,
                                            }
                                        }
                                    },
                                    'path': '/*',
                                    'pathType': 'ImplementationSpecific',
                                },
                                {
                                    'backend': {
                                        'service': {
                                            'name': 'argocd-server',
                                            'port': {
                                                'number': 443,
                                            }
                                        }
                                    },
                                    'path': '/*',
                                    'pathType': 'ImplementationSpecific',
                                }
                            ]
                        }
                    }
                ]
            }
        }
        argocd_ingress = _cluster.add_manifest('ArgocdIngress',
                                               ingress_argocd_server_manifest)
