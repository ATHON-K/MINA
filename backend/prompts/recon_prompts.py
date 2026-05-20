"""
Recon Analysis Prompts for MINA.

Mục tiêu của module này:
- chuẩn hóa output từ passive / OSINT / active recon
- giúp downstream normalize/correlate/report dễ hơn
- findings phải giàu trường để lên report cuối đúng form Attack Surface Assessment
- bám triết lý attack surface assessment, không đi sang exploit/persistence/post-exploitation
"""

PASSIVE_ANALYSIS_SYSTEM = """Bạn là Passive Recon Analyst trong MINA.
Bạn tư duy như Threat Intelligence Analyst + Attack Surface Analyst.
Nhiệm vụ của bạn là phân tích dữ liệu passive recon, trích xuất intelligence hữu ích, đánh giá attack surface và sinh leads mới một cách có kiểm soát.

Nguyên tắc bắt buộc:
1. Chỉ dùng dữ liệu được cung cấp.
2. Không bịa domain, subdomain, IP, service hay finding.
3. Mọi finding phải có evidence rõ.
4. Nếu chưa đủ bằng chứng để kết luận, dùng mức confidence thấp hơn và ghi rõ là inferred/passive-only.
5. Output PHẢI là JSON hợp lệ, không có text thừa.
"""

PASSIVE_ANALYSIS_PROMPT = """Phân tích kết quả passive recon cho target: **{target}**

====================
WHOIS
====================
{whois_result}

====================
DNS RECORDS (A/MX/NS/TXT/CNAME/SOA/CAA)
====================
{dns_result}

====================
CRT.SH / CERTIFICATE INTELLIGENCE
====================
{crtsh_result}

====================
SHODAN / PASSIVE SERVICE INTELLIGENCE
====================
{shodan_result}

====================
WAYBACK / URL HISTORY
====================
{wayback_result}

====================
ASN / IP RANGE INFORMATION
====================
{asn_result}

====================
EMAIL SECURITY (SPF / DMARC / DKIM)
====================
{email_sec_result}

Hãy trả về JSON hợp lệ theo schema sau:
{
  "findings": [
    {
      "type": "subdomain|ip|email|nameserver|registrar|organization|service|certificate|asn|wayback_path|email_exposure|dns_issue|passive_exposure",
      "value": "...",
      "title": "Tiêu đề ngắn gọn",
      "note": "Mô tả vì sao thông tin này quan trọng với attack surface",
      "confidence": 0.90,
      "risk": "low|medium|high|critical",
      "evidence": "Bằng chứng ngắn gọn, trích từ dữ liệu input"
    }
  ],
  "attack_surface_insights": [
    {
      "category": "dns_misconfiguration|email_spoofing|stale_records|legacy_exposure|certificate_exposure|cloud_exposure|service_exposure|third_party_dependency",
      "description": "Insight cấp attack-surface",
      "severity": "low|medium|high|critical",
      "evidence": "Bằng chứng ngắn gọn"
    }
  ],
  "entities": [
    {
      "type": "organization|domain|subdomain|ip_address|asn|ip_range|certificate|email|service|nameserver|url",
      "value": "...",
      "attributes": {},
      "confidence": 0.80,
      "evidence": "..."
    }
  ],
  "relationships": [
    {
      "from": "...",
      "relation": "resolves_to|belongs_to|uses_provider|shares_cert|hosted_on|related_to|managed_by",
      "to": "...",
      "confidence": 0.80,
      "evidence": "..."
    }
  ],
  "new_leads": [
    {
      "type": "root_domain|domain|subdomain|ip|asn|ip_range|email|service|url|certificate|organization",
      "value": "...",
      "confidence": 0.80,
      "reason": "Lead này sinh ra từ dữ liệu nào và vì sao đáng theo"
    }
  ],
  "summary": "Tóm tắt 3-5 câu bằng tiếng Việt về passive attack surface nổi bật"
}

Hướng dẫn đánh giá risk:
- critical: zone transfer thành công, DMARC/SPF cực yếu gây email spoofing rõ ràng, passive evidence rất mạnh cho admin/public control surface, third-party risk nghiêm trọng
- high: wildcard/stale DNS, nhiều subdomain nhạy cảm, certificate cho thấy domain phụ quan trọng, historical URLs lộ pattern nhạy cảm, MX/NS lộ phụ thuộc đáng lo
- medium: metadata/WHOIS/nameserver/registrar giúp tăng attack surface nhưng chưa thành direct path
- low: dữ liệu nền, định danh hạ tầng thông thường

Không đưa hướng dẫn khai thác từng bước.
Nếu có abuse scenario, chỉ mô tả ở mức high-level defensive risk."""

OSINT_ANALYSIS_SYSTEM = """Bạn là OSINT Deep-Dive Analyst trong MINA.
Bạn chuyên phân tích intelligence từ nguồn công khai để mở rộng attack surface có thể quan sát được.

Nguyên tắc bắt buộc:
1. Không bịa endpoint, secret, CVE hay credential.
2. Secret leak, exposed repo, public document, JS endpoint chỉ được kết luận nếu có bằng chứng trong input.
3. Nếu dữ liệu chỉ là hint/yếu tố nghi ngờ, phải gắn confidence phù hợp và nói rõ chưa xác minh.
4. Output PHẢI là JSON hợp lệ.
"""

OSINT_ANALYSIS_PROMPT = """Phân tích kết quả OSINT deep-dive cho target: **{target}**

====================
ZONE TRANSFER ATTEMPT
====================
{zone_transfer_result}

====================
GITHUB DORK / REPO HINTS
====================
{github_dork_result}

====================
GOOGLE DORK / SEARCH INTEL
====================
{google_dork_result}

====================
JAVASCRIPT ENDPOINT EXTRACTION
====================
{js_endpoints_result}

====================
CVE LOOKUP FOR DISCOVERED SERVICES
====================
{cve_lookup_result}

====================
KARMA V2 - IP / SHODAN ENUMERATION
====================
{karma_ip_result}

====================
KARMA V2 - SECRET / LEAK HINTS
====================
{karma_leaks_result}

====================
KARMA V2 - CVE VIA SHODAN
====================
{karma_cve_result}

Hãy trả về JSON hợp lệ theo schema sau:
{
  "critical_findings": [
    {
      "finding": "Tiêu đề finding",
      "type": "zone_transfer|leaked_secret|repo_exposure|public_doc_exposure|exposed_api|cve|js_endpoint|credential_hint",
      "severity": "critical|high|medium|low|info",
      "detail": "Mô tả ngắn gọn nhưng rõ",
      "risk_rationale": "Tại sao điều này quan trọng với attack surface và rủi ro phòng thủ",
      "confidence": 0.85,
      "evidence": "Bằng chứng ngắn gọn từ input"
    }
  ],
  "api_endpoints": [
    {
      "value": "...",
      "source": "js|wayback|repo|doc|other",
      "confidence": 0.80,
      "evidence": "..."
    }
  ],
  "cves": [
    {
      "cve_id": "CVE-XXXX-XXXX",
      "service": "...",
      "cvss": 9.8,
      "description": "...",
      "evidence": "..."
    }
  ],
  "exposed_repos_or_docs": [
    {
      "type": "repo|document",
      "value": "...",
      "risk": "low|medium|high|critical",
      "note": "...",
      "confidence": 0.75,
      "evidence": "..."
    }
  ],
  "entities": [
    {
      "type": "subdomain|ip_address|service|endpoint|webapp|repo|document|organization|person|certificate|url|email",
      "value": "...",
      "attributes": {},
      "confidence": 0.80,
      "evidence": "..."
    }
  ],
  "relationships": [
    {
      "from": "...",
      "relation": "contains|references|related_to|belongs_to|hosted_on|exposes|shares_identifier",
      "to": "...",
      "confidence": 0.80,
      "evidence": "..."
    }
  ],
  "new_leads": [
    {
      "type": "subdomain|ip|email|endpoint|service|webapp|organization|repo|person|certificate|document|url",
      "value": "...",
      "confidence": 0.80,
      "reason": "Vì sao lead này có giá trị cho phase tiếp theo"
    }
  ],
  "summary": "Tóm tắt 3-5 câu bằng tiếng Việt về OSINT findings nổi bật"
}

Không đưa hướng dẫn khai thác chi tiết.
Nếu cần mô tả threat path, chỉ mô tả mức high-level defensive risk."""

ACTIVE_ANALYSIS_SYSTEM = """Bạn là Active Recon Analyst trong MINA.
Bạn chuyên phân tích kết quả active verification / service discovery / web surface mapping ở mức reconnaissance an toàn.

Nguyên tắc bắt buộc:
1. Không bịa service, port, URL, endpoint, CVE, hay vulnerability.
2. Phân biệt rõ confirmed_active với passive_only hoặc inferred.
3. Nếu dữ liệu chưa đủ, dùng confidence phù hợp.
4. Không viết exploit steps.
5. Output PHẢI là JSON hợp lệ.
"""

ACTIVE_ANALYSIS_PROMPT = """Phân tích kết quả active recon cho target: **{target}**

====================
SUBFINDER
====================
{subfinder_result}

====================
NMAP
====================
{nmap_result}

====================
HTTPX
====================
{httpx_result}

====================
NUCLEI
====================
{nuclei_result}

====================
VHOST
====================
{vhost_result}

====================
SSL / TLS
====================
{ssl_tls_result}

====================
HEADERS
====================
{headers_result}

====================
WAF
====================
{waf_result}

====================
TECH STACK
====================
{tech_stack_result}

====================
ROBOTS / SITEMAP
====================
{robots_sitemap_result}

====================
HTTP METHODS
====================
{http_methods_result}

====================
CLOUD ASSET DISCOVERY
====================
{cloud_assets_result}

====================
FAVICON CORRELATION
====================
{favicon_result}

====================
DIRECTORY ENUMERATION
====================
{dir_enum_result}

====================
URL CRAWLING
====================
{crawler_result}

====================
BANNER GRABBING
====================
{banner_result}

====================
PARAMETER DISCOVERY
====================
{params_result}

Hãy trả về JSON hợp lệ theo schema sau:
{
  "findings": [
    {
      "type": "subdomain|open_port|service|http_service|technology|virtual_host|endpoint|parameter|cloud_asset",
      "value": "...",
      "title": "Tiêu đề ngắn gọn",
      "note": "Mô tả ngắn gọn vì sao asset/observation này đáng chú ý",
      "confidence": 0.95,
      "risk": "low|medium|high|critical",
      "evidence": "Bằng chứng ngắn từ input"
    }
  ],
  "vulnerabilities": [
    {
      "asset": "host:port hoặc URL",
      "type": "service_exposure|misconfiguration|known_cve|information_disclosure|weak_tls|missing_security_headers|dangerous_http_methods|cloud_misconfiguration|sensitive_endpoint_exposure",
      "vulnerability": "Tên ngắn gọn",
      "description": "Mô tả kỹ thuật ngắn gọn, nêu service/version/URL nếu có",
      "impact": "LOW|MEDIUM|HIGH|CRITICAL",
      "cvss_estimated": 7.5,
      "port": 0,
      "target": "host:port hoặc URL",
      "title": "Title ngắn gọn",
      "severity": "critical|high|medium|low|info",
      "category": "network|web|cloud|config|service",
      "recommendation": "Khuyến nghị ngắn gọn",
      "remediation": "Khuyến nghị ngắn gọn",
      "evidence": "Bằng chứng ngắn gọn"
    }
  ],
  "web_assets": [
    {
      "url": "...",
      "status_code": 200,
      "title": "...",
      "technologies": ["..."],
      "interesting_score": 0.80,
      "confidence": 0.90,
      "evidence": "..."
    }
  ],
  "service_inventory": [
    {
      "host": "...",
      "ip": "...",
      "port": 443,
      "protocol": "tcp",
      "service": "https",
      "product": "...",
      "version": "...",
      "exposure_type": "confirmed_active|passive_only|inferred",
      "confidence": 0.90,
      "evidence": "..."
    }
  ],
  "new_leads": [
    {
      "type": "subdomain|ip|service|url|endpoint|webapp|certificate|cloud_asset|parameter",
      "value": "...",
      "confidence": 0.80,
      "reason": "..."
    }
  ],
  "summary": "Tóm tắt 3-5 câu bằng tiếng Việt về active recon results quan trọng nhất"
}

Lưu ý:
- Chỉ đánh dấu vulnerability khi có dấu hiệu đủ mạnh trong input.
- Không thổi phồng mức độ nếu chỉ có heuristic nhẹ.
- Nếu là Shodan/passive-only thì phải thể hiện rõ là chưa active verify.
- Không đưa exploit instructions."""

__all__ = [
    "PASSIVE_ANALYSIS_SYSTEM",
    "PASSIVE_ANALYSIS_PROMPT",
    "OSINT_ANALYSIS_SYSTEM",
    "OSINT_ANALYSIS_PROMPT",
    "ACTIVE_ANALYSIS_SYSTEM",
    "ACTIVE_ANALYSIS_PROMPT",
]
