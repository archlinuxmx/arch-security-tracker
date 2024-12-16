from .conftest import create_group


@create_group(issues=['CVE-2025-9999999', 'CVE-2025-10000000',
                      'CVE-2026-0001', 'CVE-2026-10000'])
def test_group_orders_cves_by_year_then_number(db, client):
    expected = ['CVE-2026-10000', 'CVE-2026-0001',
                'CVE-2025-10000000', 'CVE-2025-9999999']
    response = client.get('/AVG-1.json')
    assert response.status_code == 200
    assert response.get_json()['issues'] == expected
    page = client.get('/AVG-1').get_data(as_text=True)
    positions = [page.index('href="/{}"'.format(name)) for name in expected]
    assert positions == sorted(positions)
