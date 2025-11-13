# Hybrid Geolocation Strategy

## Problem
Currently limiting to 10 API lookups means we only detect 9 countries from 8,453 IPs.
This is inaccurate - we need country data for ALL IPs, not just top 10.

## Solution: Two-Tier Hybrid Approach

### Tier 1: Free Offline Database (ALL IPs)
**Purpose**: Get country/city for ALL 8,453 IPs
**Options**:
1. **MaxMind GeoLite2** (Recommended)
   - Free account required (no credit card)
   - Download ~70MB .mmdb database file
   - Python library: `geoip2` or `maxminddb`
   - Updates: Monthly (manual download or API)
   - Accuracy: ~99% for country, ~80% for city
   - Data: Country, City, Coordinates
   - **Does NOT include**: ISP/Organization info

2. **IP2Location LITE**
   - Free download (no account needed)
   - Similar accuracy to GeoLite2
   - Python library: `IP2Location`
   - Alternative if MaxMind signup is issue

### Tier 2: ipinfo.io API (Top X IPs Only)
**Purpose**: Enrich top X attackers with ISP/Org details
**Data**: Organization, ISP, ASN, detailed city info
**Limit**: Configurable (default: 10)
**Cost**: 50,000 requests/month free

## Implementation Plan

### Step 1: Install Dependencies
```bash
pip install geoip2 maxminddb
```

### Step 2: Download GeoLite2 Database
**Option A: Manual Download** (Recommended for testing)
1. Sign up at https://www.maxmind.com/en/geolite2/signup
2. Download GeoLite2-City.mmdb or GeoLite2-Country.mmdb
3. Place in project root or `hq/` folder
4. Add to .env: `GEOIP2_DB_PATH=./GeoLite2-Country.mmdb`

**Option B: Automated Download** (For production)
- Use MaxMind GeoIP Update tool
- Or use `geoip2` library with license key

### Step 3: Update LQE Logic

```python
def map_geographic_threats(self, ...):
    # TIER 1: Use free offline DB for ALL IPs (country only)
    ip_to_country = {}
    
    if geoip2_db_path and os.path.exists(geoip2_db_path):
        import geoip2.database
        reader = geoip2.database.Reader(geoip2_db_path)
        
        for ip in unique_ips:
            try:
                response = reader.country(ip)  # or .city(ip)
                ip_to_country[ip] = {
                    'country_code': response.country.iso_code,
                    'country_name': response.country.name,
                    'city': None,  # or response.city.name if using City DB
                    'org': None,   # Not available in free DB
                    'source': 'geoip2_free'
                }
            except:
                pass  # IP not found or invalid
        
        reader.close()
    
    # TIER 2: Enrich top X IPs with ipinfo.io (for org/ISP details)
    if ipinfo_token and max_api_lookups > 0:
        # Get top X most frequent attacker IPs
        top_ips = get_top_n_ips(entries, max_api_lookups)
        
        # Call ipinfo API for these IPs only
        details = ipinfo_handler.getBatchDetails(top_ips)
        
        # Merge/override with detailed data
        for ip, detail in details.items():
            if ip in ip_to_country:
                # Enhance existing entry with org info
                ip_to_country[ip]['org'] = detail.get('org')
                ip_to_country[ip]['city'] = detail.get('city')
                ip_to_country[ip]['source'] = 'ipinfo_enhanced'
            else:
                # Add new entry (shouldn't happen if geoip2 worked)
                ip_to_country[ip] = {
                    'country_code': detail.get('country'),
                    'country_name': detail.get('country_name'),
                    'city': detail.get('city'),
                    'org': detail.get('org'),
                    'source': 'ipinfo_only'
                }
```

## Expected Results

### Before (Current):
```
✅ Total unique IPs: 8,453
✅ Countries detected: 9  ❌ WRONG!
✅ API lookups: 10
```

### After (Hybrid):
```
✅ Total unique IPs: 8,453
✅ Countries detected: 45-60  ✅ ACCURATE!
✅ GeoIP2 lookups: 8,453 (offline, instant)
✅ ipinfo API lookups: 10 (top attackers only)
✅ IPs with org details: 10
```

## Benefits

1. **Accurate country counts** - All IPs mapped to countries
2. **Stay within API quota** - Only use paid API for top threats
3. **Fast** - Offline DB lookups are instant (no network calls)
4. **Cost effective** - 99% free, 1% paid API
5. **Detailed where it matters** - Top attackers get full ISP/org info

## Database Size & Performance

- **GeoLite2-Country.mmdb**: ~6MB (country only)
- **GeoLite2-City.mmdb**: ~70MB (country + city)
- **Lookup speed**: ~0.001ms per IP (in-memory)
- **8,453 IPs**: ~8 seconds total (vs 10+ minutes with API)

## Alternative: IP2Location LITE

If MaxMind signup is an issue:

```bash
pip install IP2Location
```

Download from: https://lite.ip2location.com/database/ip-country
- No account needed
- CSV format (convert to binary for speed)
- Similar accuracy

## Recommendation

**Use MaxMind GeoLite2-Country.mmdb**:
- Most widely used
- Best documentation
- Easy Python integration
- Small file size (6MB)
- Monthly updates sufficient for country-level data

**Configuration**:
```env
# .env
GEOIP2_DB_PATH=./GeoLite2-Country.mmdb
IPINFO_TOKEN=6965d968d327e7
IPINFO_MAX_LOOKUPS=10
```

**Fallback chain**:
1. Try GeoIP2 offline DB (all IPs)
2. If not available, try ipinfo API (limited to max_lookups)
3. If neither available, return error

This gives us **best of both worlds**: comprehensive coverage + detailed intel on top threats.

