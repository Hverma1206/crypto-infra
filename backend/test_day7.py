from app import app


def test_domain_analysis():
    client = app.test_client()
    response = client.post("/analyze", json={"input": "github.com"})
    data = response.get_json()
    print("Status:", response.status_code)
    print("Nodes:", len(data.get("nodes", [])))
    print("Edges:", len(data.get("edges", [])))
    print("Risk:", data.get("risk"))
    assert response.status_code == 200
    assert data.get("nodes")
    assert "risk" in data


if __name__ == "__main__":
    test_domain_analysis()
    print("Day 7 PASS")
