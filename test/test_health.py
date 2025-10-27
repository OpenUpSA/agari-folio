def test_database_health(client):
    """Test that the /info/health/db endpoint returns 200"""
    response = client.get('/info/health/db')
    
    assert response.status_code == 200
    data = response.get_json()
    assert data.get('status') == 'healthy'
