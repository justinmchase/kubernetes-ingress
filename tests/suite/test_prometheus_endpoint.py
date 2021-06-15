import pytest
import requests

from kubernetes.client import V1ContainerPort

from suite.resources_utils import (
    ensure_connection_to_public_endpoint,
    create_items_from_yaml,
    create_example_app,
    delete_common_app,
    delete_items_from_yaml,
    wait_until_all_pods_are_ready,
    delete_secret,
    create_secret_from_yaml,
)
from suite.yaml_utils import get_first_ingress_host_from_yaml
from settings import TEST_DATA


class IngressSetup:
    """
    Encapsulate the Smoke Example details.

    Attributes:
        ingress_host (str):
    """

    def __init__(self, ingress_host):
        self.ingress_host = ingress_host


@pytest.fixture(scope="class")
def prometheus_setup(request, kube_apis, test_namespace):
    print("------------------------- Deploy Prometheus Secret -----------------------------------")
    prometheus_secret_name = create_secret_from_yaml(
        kube_apis.v1, "nginx-ingress", f"{TEST_DATA}/prometheus/secret.yaml"
    )

    def fin():
        delete_secret(kube_apis.v1, prometheus_secret_name, "nginx-ingress")

    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def enable_exporter_port(
        cli_arguments, kube_apis, ingress_controller_prerequisites, ingress_controller
) -> None:
    """
    Set containerPort for Prometheus Exporter.

    :param cli_arguments: context
    :param kube_apis: client apis
    :param ingress_controller_prerequisites
    :param ingress_controller: IC name
    :return:
    """
    namespace = ingress_controller_prerequisites.namespace
    port = V1ContainerPort(9113, None, None, "prometheus", "TCP")
    print("------------------------- Enable 9113 port in IC -----------------------------------")
    body = kube_apis.apps_v1_api.read_namespaced_deployment(ingress_controller, namespace)
    body.spec.template.spec.containers[0].ports.append(port)

    if cli_arguments["deployment-type"] == "deployment":
        kube_apis.apps_v1_api.patch_namespaced_deployment(ingress_controller, namespace, body)
    else:
        kube_apis.apps_v1_api.patch_namespaced_daemon_set(ingress_controller, namespace, body)
    wait_until_all_pods_are_ready(kube_apis.v1, namespace)


@pytest.fixture(scope="class")
def ingress_setup(request, kube_apis, ingress_controller_endpoint, test_namespace) -> IngressSetup:
    print("------------------------- Deploy Ingress Example -----------------------------------")
    secret_name = create_secret_from_yaml(
        kube_apis.v1, test_namespace, f"{TEST_DATA}/smoke/smoke-secret.yaml"
    )
    create_items_from_yaml(
        kube_apis, f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml", test_namespace
    )
    ingress_host = get_first_ingress_host_from_yaml(
        f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml"
    )
    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )

    def fin():
        print("Clean up simple app")
        delete_common_app(kube_apis, "simple", test_namespace)
        delete_items_from_yaml(
            kube_apis, f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml", test_namespace
        )
        delete_secret(kube_apis.v1, secret_name, test_namespace)

    request.addfinalizer(fin)

    return IngressSetup(ingress_host)


@pytest.mark.demo
class TestPrometheusEndpoint:
    @pytest.mark.parametrize(
        "ingress_controller, expected_metrics",
        [
            pytest.param(
                {"extra_args": ["-enable-prometheus-metrics", "-enable-latency-metrics", "-prometheus-tls-secret=nginx-ingress/prometheus-test-secret"]},
                [
                    'nginx_ingress_controller_ingress_resources_total{class="nginx",type="master"} 0',
                    'nginx_ingress_controller_ingress_resources_total{class="nginx",type="minion"} 0',
                ],
            )
        ],
        indirect=["ingress_controller"],
    )
    def test_https_metrics(
            self,
            prometheus_setup,
            ingress_controller_endpoint,
            ingress_controller,
            enable_exporter_port,
            expected_metrics,
            ingress_setup,
    ):
        resp = {}

        # assert http fails
        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
        try:
            resp = requests.get(req_url, verify=False)
        except:
            print("request fails as expected")

        assert resp.status_code == 400, f"Expected 400 code for http request to /metrics but got {resp.status_code}"

        # assert https succeeds
        req_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
        resp = requests.get(req_url, verify=False)

        assert resp.status_code == 200, f"Expected 200 code for /metrics but got {resp.status_code}"

        resp_content = resp.content.decode("utf-8")
        for item in expected_metrics:
            assert item in resp_content

