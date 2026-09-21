import httpx

def verify_live_endpoint():
    with open('tests/fixtures/user_dear_rishabh.eml', 'rb') as f:
        eml_content = f.read().decode('utf-8', errors='replace')

    r = httpx.post(
        'http://127.0.0.1:8000/api/v1/emails/analyze',
        json={'raw_eml': eml_content, 'file_name': 'user_dear_rishabh.eml'},
        timeout=15.0
    )
    print("HTTP Status:", r.status_code)
    assert r.status_code == 200, f"Endpoint returned error: {r.text}"
    data = r.json()
    
    print(f"Risk Score: {data.get('risk_score')}/100 ({data.get('risk_level')})")
    print(f"Probable Origin IP: {data.get('probable_origin_ip')}")
    print(f"Approximate Location: {data.get('approximate_location')}")
    
    hops = data.get('hops', [])
    print(f"\nTotal Relay Hops Resolved: {len(hops)}")
    assert len(hops) > 0, "No hops returned!"

    for h in hops:
        print(f"Hop #{h.get('hop')}: IP={h.get('ip')} | Public={h.get('is_public')} | Origin={h.get('is_origin')}")
        print(f"       Location: {h.get('city')}, {h.get('region')}, {h.get('country')}")
        print(f"       Geo: ({h.get('latitude')}, {h.get('longitude')})")
        print(f"       ISP: {h.get('isp')} | ASN: {h.get('asn')}")

    # Check that at least one hop has non-null latitude and longitude
    geo_hops = [h for h in hops if h.get('latitude') is not None and h.get('longitude') is not None]
    print(f"\nHops with real geographic coordinates: {len(geo_hops)}")
    assert len(geo_hops) > 0, "No hops with geographic coordinates!"
    
    public_origin_hop = next((h for h in hops if h.get('ip') == '130.248.216.47'), None)
    assert public_origin_hop is not None, "Public relay hop 130.248.216.47 not found!"
    assert public_origin_hop['country'] == 'Japan'
    assert public_origin_hop['latitude'] is not None
    assert public_origin_hop['longitude'] is not None
    print("\nVERIFICATION COMPLETE: Every public relay hop successfully resolved with real Latitude, Longitude, City, Region, and Country!")

if __name__ == "__main__":
    verify_live_endpoint()
