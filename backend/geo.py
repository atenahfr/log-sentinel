import requests
import time

# This dictionary acts as a cache — stores results we've already looked up
# so we don't query the same IP twice
_cache = {}

def lookup_ip(ip):
    """
    Looks up the geographic location of an IP address.
    
    Args:
        ip: string, the IP address to look up
    
    Returns:
        A dictionary with country, city, region, isp fields
        Or a dictionary with 'error' field if lookup failed
    """

    # Step 1: check cache first — if we've seen this IP before, return stored result
    if ip in _cache:
        return _cache[ip]

    # Step 2: call the API
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)
        data = response.json()

        # Step 3: check if the API returned a successful result
        if data.get('status') == 'success':
            result = {
                'country':  data.get('country', 'Unknown'),
                'region':   data.get('regionName', 'Unknown'),
                'city':     data.get('city', 'Unknown'),
                'isp':      data.get('isp', 'Unknown'),
                'lat':      data.get('lat', 0),
                'lon':      data.get('lon', 0),
            }
        else:
            result = {'error': data.get('message', 'Lookup failed')}

        # Step 4: store in cache before returning
        _cache[ip] = result

        # Step 5: rate limiting — wait 1.5 seconds between requests
        # Free tier allows 45 requests/minute = 1 every 1.33 seconds
        time.sleep(1.5)

        return result

    except requests.exceptions.RequestException as e:
        error_result = {'error': str(e)}
        _cache[ip] = error_result
        return error_result


def enrich_flagged_ips(flagged_ips):
    """
    Takes a list of flagged IP addresses and adds geo data to each one.
    
    Args:
        flagged_ips: a list of IP address strings
    
    Returns:
        A dictionary mapping each IP to its geo data
    """
    results = {}
    total = len(flagged_ips)

    for i, ip in enumerate(flagged_ips):
        print(f"Looking up {ip} ({i+1}/{total})...")
        
        # Skip private/internal IP ranges — they can't be geolocated
        if (ip.startswith('192.168.') or 
            ip.startswith('10.') or 
            ip.startswith('172.16.')):
            results[ip] = {'error': 'private IP — not routable on public internet'}
            continue
            
        results[ip] = lookup_ip(ip)

    return results


if __name__ == '__main__':
    # Test with our flagged IPs from previous days
    test_ips = ['45.33.32.156', '198.51.100.23', '203.0.113.77']
    
    print("=== GEO-IP LOOKUP RESULTS ===\n")
    geo_data = enrich_flagged_ips(test_ips)
    
    for ip, data in geo_data.items():
        print(f"IP: {ip}")
        for key, value in data.items():
            print(f"  {key}: {value}")
        print()