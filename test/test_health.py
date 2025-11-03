def test_database_health(client):
    """Test that the /info/health/db endpoint returns 200"""
    response = client.get('/info/health/db')
    assert response.status_code == 200

    # Optionally, check the response data
    data = response.get_json()
    assert data is not None
    assert data.get('status') == 'healthy'
