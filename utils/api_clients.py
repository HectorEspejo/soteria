import logging
import requests
import time
import hashlib
from typing import Dict, Optional, Any, List
from datetime import datetime, timedelta
import json
from urllib.parse import quote

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, max_calls: int, period: int):
        self.max_calls = max_calls
        self.period = period
        self.calls = []
    
    def wait_if_needed(self):
        now = time.time()
        self.calls = [call_time for call_time in self.calls 
                     if now - call_time < self.period]
        
        if len(self.calls) >= self.max_calls:
            sleep_time = self.period - (now - self.calls[0]) + 0.1
            logger.debug(f"Rate limit reached, sleeping for {sleep_time:.1f}s")
            time.sleep(sleep_time)
        
        self.calls.append(now)

class APICache:
    def __init__(self, ttl: int = 3600):
        self.cache = {}
        self.ttl = ttl
    
    def get(self, key: str) -> Optional[Any]:
        if key in self.cache:
            data, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return data
            else:
                del self.cache[key]
        return None
    
    def set(self, key: str, value: Any):
        self.cache[key] = (value, time.time())
    
    def clear_expired(self):
        now = time.time()
        expired_keys = [key for key, (_, timestamp) in self.cache.items() 
                       if now - timestamp >= self.ttl]
        for key in expired_keys:
            del self.cache[key]

class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}
        self.rate_limiter = RateLimiter(max_calls=4, period=60)
        self.cache = APICache(ttl=3600)
        self.is_valid = self._validate_api_key()
    
    def _validate_api_key(self) -> bool:
        """Check if API key is valid (not a placeholder)"""
        if not self.api_key or self.api_key.startswith("YOUR_") or len(self.api_key) < 10:
            logger.warning("VirusTotal API key not configured or invalid")
            return False
        return True
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        if not self.is_valid:
            return {"error": "API key not configured", "malicious": False, "score": 0}
        
        cache_key = f"vt_url:{url}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        try:
            self.rate_limiter.wait_if_needed()
            
            url_id = self._get_url_id(url)
            response = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 404:
                scan_response = requests.post(
                    f"{self.base_url}/urls",
                    headers=self.headers,
                    data={"url": url},
                    timeout=10
                )
                scan_response.raise_for_status()
                
                time.sleep(15)
                
                response = requests.get(
                    f"{self.base_url}/urls/{url_id}",
                    headers=self.headers,
                    timeout=10
                )
            
            response.raise_for_status()
            data = response.json()
            
            result = self._parse_url_result(data)
            self.cache.set(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"VirusTotal URL scan error: {e}")
            return {"error": str(e), "malicious": False, "score": 0}
    
    def scan_file_hash(self, file_hash: str) -> Dict[str, Any]:
        if not self.is_valid:
            return {"error": "API key not configured", "malicious": False, "score": 0}
        
        cache_key = f"vt_hash:{file_hash}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        try:
            self.rate_limiter.wait_if_needed()
            
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 404:
                return {"error": "File not found", "malicious": False, "score": 0}
            
            response.raise_for_status()
            data = response.json()
            
            result = self._parse_file_result(data)
            self.cache.set(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"VirusTotal file scan error: {e}")
            return {"error": str(e), "malicious": False, "score": 0}
    
    def _get_url_id(self, url: str) -> str:
        return requests.utils.quote(url, safe='')
    
    def _parse_url_result(self, data: Dict) -> Dict[str, Any]:
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        total = sum(stats.values())
        malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
        
        score = (malicious / total * 100) if total > 0 else 0
        
        return {
            'malicious': malicious > 0,
            'score': score,
            'detections': f"{malicious}/{total}",
            'categories': attributes.get('categories', {}),
            'last_analysis_date': attributes.get('last_analysis_date')
        }
    
    def _parse_file_result(self, data: Dict) -> Dict[str, Any]:
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        total = sum(stats.values())
        malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
        
        score = (malicious / total * 100) if total > 0 else 0
        
        return {
            'malicious': malicious > 0,
            'score': score,
            'detections': f"{malicious}/{total}",
            'file_type': attributes.get('type_description'),
            'file_names': attributes.get('names', [])[:5],
            'last_analysis_date': attributes.get('last_analysis_date')
        }

class AbuseIPDBClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {"Key": api_key, "Accept": "application/json"}
        self.rate_limiter = RateLimiter(max_calls=1000, period=86400)
        self.cache = APICache(ttl=3600)
    
    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        cache_key = f"abuseipdb:{ip_address}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        try:
            self.rate_limiter.wait_if_needed()
            
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": "90",
                "verbose": ""
            }
            
            response = requests.get(
                f"{self.base_url}/check",
                headers=self.headers,
                params=params,
                timeout=10
            )
            
            response.raise_for_status()
            data = response.json()
            
            result = self._parse_result(data)
            self.cache.set(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"AbuseIPDB check error: {e}")
            return {"error": str(e), "malicious": False, "score": 0}
    
    def report_ip(self, ip_address: str, categories: List[int], comment: str = ""):
        try:
            self.rate_limiter.wait_if_needed()
            
            data = {
                "ip": ip_address,
                "categories": ",".join(map(str, categories)),
                "comment": comment[:1024]
            }
            
            response = requests.post(
                f"{self.base_url}/report",
                headers=self.headers,
                data=data,
                timeout=10
            )
            
            response.raise_for_status()
            logger.info(f"Reported IP {ip_address} to AbuseIPDB")
            
        except Exception as e:
            logger.error(f"AbuseIPDB report error: {e}")
    
    def _parse_result(self, data: Dict) -> Dict[str, Any]:
        ip_data = data.get('data', {})
        
        return {
            'malicious': ip_data.get('abuseConfidenceScore', 0) > 50,
            'score': ip_data.get('abuseConfidenceScore', 0),
            'country': ip_data.get('countryCode'),
            'usage_type': ip_data.get('usageType'),
            'isp': ip_data.get('isp'),
            'total_reports': ip_data.get('totalReports', 0),
            'last_reported': ip_data.get('lastReportedAt')
        }

class GoogleSafeBrowsingClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://safebrowsing.googleapis.com/v4"
        self.rate_limiter = RateLimiter(max_calls=10000, period=86400)
        self.cache = APICache(ttl=1800)
        self.is_valid = self._validate_api_key()
    
    def _validate_api_key(self) -> bool:
        """Check if API key is valid (not a placeholder)"""
        if not self.api_key or self.api_key.startswith("YOUR_") or len(self.api_key) < 10:
            logger.warning("Google Safe Browsing API key not configured or invalid")
            return False
        return True
    
    def check_url(self, url: str) -> Dict[str, Any]:
        if not self.is_valid:
            return {"error": "API key not configured", "malicious": False, "score": 0}
        
        cache_key = f"gsb:{url}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        try:
            self.rate_limiter.wait_if_needed()
            
            request_body = {
                "client": {
                    "clientId": "soteria-ids",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(
                f"{self.base_url}/threatMatches:find?key={self.api_key}",
                json=request_body,
                timeout=10
            )
            
            response.raise_for_status()
            data = response.json()
            
            result = self._parse_result(data, url)
            self.cache.set(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Google Safe Browsing error: {e}")
            return {"error": str(e), "malicious": False, "score": 0}
    
    def _parse_result(self, data: Dict, url: str) -> Dict[str, Any]:
        matches = data.get('matches', [])
        
        if not matches:
            return {
                'malicious': False,
                'score': 0,
                'threat_types': []
            }
        
        threat_types = [match.get('threatType') for match in matches]
        
        score_map = {
            'MALWARE': 100,
            'SOCIAL_ENGINEERING': 90,
            'UNWANTED_SOFTWARE': 70,
            'POTENTIALLY_HARMFUL_APPLICATION': 60
        }
        
        max_score = max(score_map.get(tt, 50) for tt in threat_types)
        
        return {
            'malicious': True,
            'score': max_score,
            'threat_types': threat_types,
            'platform_types': [match.get('platformType') for match in matches]
        }

def get_file_hash(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()