import email
from app.services.intelligence.ip_enrichment import ip_enrichment_service
from app.api.v1.endpoints.emails import extract_ips_from_text, is_public_ip

def test_live_geoip_resolution():
    with open('tests/fixtures/user_dear_rishabh.eml', 'rb') as f:
        raw = f.read().decode('utf-8', errors='replace')

    msg = email.message_from_string(raw)
    received = msg.get_all('Received') or []

    all_ips = []
    for r in received:
        for ip in extract_ips_from_text(r):
            if ip not in all_ips:
                all_ips.append(ip)

    print(f"Extracted IPs from Received headers: {all_ips}")
    geo_res = ip_enrichment_service.batch_query_geoip(all_ips)
    
    assert len(geo_res) > 0
    for ip, data in geo_res.items():
        print(f"IP: {ip} -> City: {data.get('city')}, Region: {data.get('regionName')}, Country: {data.get('country')}, Lat/Lon: ({data.get('latitude')}, {data.get('longitude')}), ISP: {data.get('isp')}")

    # Verify public relay IP 130.248.216.47
    public_hop = geo_res.get("130.248.216.47")
    assert public_hop is not None
    assert public_hop["latitude"] is not None
    assert public_hop["longitude"] is not None
    assert public_hop["country"] == "Japan"
    assert "Tokyo" in (public_hop.get("regionName") or "")
    print("SUCCESS: 130.248.216.47 verified with real Latitude, Longitude, City, Region, and Country!")

    # Verify private IP
    priv_hop = geo_res.get("10.1.1.231")
    assert priv_hop is not None
    assert priv_hop["is_private"] is True
    assert priv_hop["country"] == "Private Network"
    print("SUCCESS: Private relay hop verified with RFC-1918 classification!")

if __name__ == "__main__":
    test_live_geoip_resolution()
