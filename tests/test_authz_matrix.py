from checks.authz_matrix import EndpointClassification, ProfileObservation, classify_endpoint, compare_observations
from checks.endpoint_inventory import InventoryEndpoint


def test_classify_endpoint_marks_admin_and_object_reference_candidates() -> None:
    classification = classify_endpoint('https://example.com/admin/orders/12345')

    assert classification.category == 'privileged'
    assert 'privileged' in classification.tags
    assert 'object-reference-candidate' in classification.tags


def test_compare_observations_flags_suspicious_privileged_similarity() -> None:
    endpoint = InventoryEndpoint(
        url='https://example.com/admin',
        requested_url='https://example.com/admin',
        status_code=200,
        content_type='text/html',
        title='Admin',
        depth=1,
    )
    classification = EndpointClassification(
        category='privileged',
        tags=['privileged'],
        rationale=["Path contains 'admin'."],
    )
    observations = [
        ProfileObservation('guest', 200, None, 1024, {'location': None}, {'login': False}),
        ProfileObservation('user', 200, None, 1024, {'location': None}, {'login': False}),
        ProfileObservation('admin', 200, None, 1024, {'location': None}, {'login': False}),
    ]

    findings = compare_observations(endpoint, classification, observations)

    assert any(finding.title == 'Privileged endpoint looks equally reachable to guest' for finding in findings)
