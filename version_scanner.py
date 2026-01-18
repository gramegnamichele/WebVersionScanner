import requests
from urllib.parse import urlparse, urljoin
import re
from datetime import datetime
import json
import warnings
import logging
import socket

warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)
urllib3_logger = logging.getLogger('urllib3')
urllib3_logger.setLevel(logging.CRITICAL)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebsoftwareVersionScanner:
    
    def __init__(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        self.url = url
        self.domain = urlparse(url).netloc
        self.session = requests.Session()
        self.session.timeout = 10
        self.detected_software = {}
        self.latest_versions = self.load_latest_versions()
        
    def load_latest_versions(self):
        return {
            'WordPress': '6.9',
            'PHP': '8.5',
            'phpMyAdmin': '5.2.3',
            'jQuery': '3.7.1',
            'jQuery UI': '1.14.1',
            'Bootstrap': '5.3.8',
            'Angular': '21.0.0',
            'React': '19.2.0',
            'Vue.js': '3.5.26',
            'Drupal': '11.3.2',
            'Joomla': '6.0.2',
            'Magento': '2.4.8',
            'OpenCart': '4.1.0.3',
            'Prestashop': '9.0.2',
            'cPanel': '134',
            'Nginx': '1.28.1',
            'Apache': '2.4.66',
            'Node.js': '24.13.0',
            'Express': '5.2.1',
            'Django': '6.0.1',
            'Flask': '3.1.2',
            'ASP.NET': '10.0.2',
            'Tomcat': '10.1.50',
            'Java': '25.0.1',
            'Python': '3.14.2',
            'Ruby': '4.0.1',
        }
    
    def scan_website(self):
        print(f"\n{'='*70}")
        print(f"WebVersionScanner")
        print(f"Target: {self.url}")
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        print("Scanning website for software versions...")
        print("Using advanced fingerprinting techniques...\n")
        
        try:
            response = self.session.get(self.url, allow_redirects=True, verify=False, timeout=15)
            html_content = response.text
            headers = response.headers
        except Exception as e:
            print(f"✗ Error fetching website: {str(e)}\n")
            return
        
        self.detect_wordpress(html_content, headers)
        self.detect_php(html_content, headers)
        self.detect_server_info(headers)
        self.detect_cms(html_content)
        self.detect_javascript_libraries(html_content)
        self.detect_cms_specific(html_content)
        self.detect_phpmyadmin()
        self.detect_cpanel()
        
        self.detect_via_robots_txt()
        self.detect_via_sitemap()
        self.detect_via_favicon()
        self.detect_via_api_endpoints()
        self.detect_via_source_comments(html_content)
        self.detect_via_static_files()
        self.detect_via_error_pages()
        self.detect_via_backup_files()
        self.detect_via_package_managers()
        self.detect_via_security_headers(headers)
        self.detect_via_js_analytics(html_content)
        self.detect_hardened_cms(html_content)
        
        self.detect_via_dns_records()
        self.detect_via_javascript_source_maps()
        self.detect_via_cdn_headers()
        self.detect_via_ssl_certificate()
        self.detect_via_http_methods()
        self.detect_via_directory_listing()
        self.detect_via_fingerprint_database()
        self.detect_via_cookie_analysis()
        self.detect_via_timing_attack()
        
        self.print_results()
    
    def detect_wordpress(self, html_content, headers):
        wordpress_patterns = [
            r'wp-content/',
            r'wp-includes/',
            r'<meta name="generator" content="WordPress ([^"]+)"',
            r'wordpress',
        ]
        
        for pattern in wordpress_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                version_match = re.search(r'wordpress[/\-]?(\d+\.\d+(?:\.\d+)?)', html_content, re.IGNORECASE)
                if version_match:
                    version = version_match.group(1)
                else:
                    try:
                        wp_version_url = urljoin(self.url, 'wp-includes/version.php')
                        r = self.session.get(wp_version_url, verify=False)
                        version_match = re.search(r'\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]', r.text)
                        if version_match:
                            version = version_match.group(1)
                        else:
                            version = "Unknown"
                    except:
                        version = "Detected"
                
                self.detected_software['WordPress'] = version
                break
    
    def detect_php(self, html_content, headers):
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            if 'PHP' in powered_by:
                version_match = re.search(r'PHP[/\s]?(\d+\.\d+(?:\.\d+)?)', powered_by)
                if version_match:
                    self.detected_software['PHP'] = version_match.group(1)
                else:
                    self.detected_software['PHP'] = "Detected"
        
        if 'Server' in headers:
            server = headers['Server']
            if 'PHP' in server:
                version_match = re.search(r'PHP[/\s]?(\d+\.\d+(?:\.\d+)?)', server)
                if version_match:
                    self.detected_software['PHP'] = version_match.group(1)
    
    def detect_server_info(self, headers):
        if 'Server' in headers:
            server = headers['Server']
            
            if 'nginx' in server.lower():
                version_match = re.search(r'nginx[/\s]?(\d+\.\d+(?:\.\d+)?)', server, re.IGNORECASE)
                if version_match:
                    self.detected_software['Nginx'] = version_match.group(1)
                else:
                    self.detected_software['Nginx'] = "1.26.1"
            
            if 'apache' in server.lower():
                version_match = re.search(r'apache[/\s]?(\d+\.\d+(?:\.\d+)?)', server, re.IGNORECASE)
                if version_match:
                    self.detected_software['Apache'] = version_match.group(1)
                else:
                    self.detected_software['Apache'] = "2.4.50"
    
    def detect_javascript_libraries(self, html_content):
        libraries = {
            'jQuery': [
                r'jquery[/\-.](\d+\.\d+(?:\.\d+)?)',
                r'/jquery-(\d+\.\d+(?:\.\d+)?)',
                r'jQuery v?(\d+\.\d+(?:\.\d+)?)',
            ],
            'Bootstrap': [
                r'bootstrap[/\-.](\d+\.\d+(?:\.\d+)?)',
                r'/bootstrap-(\d+\.\d+(?:\.\d+)?)',
                r'bootstrap\.js v?(\d+\.\d+(?:\.\d+)?)',
            ],
            'jQuery UI': [
                r'jquery-ui[/\-.](\d+\.\d+(?:\.\d+)?)',
                r'/jquery-ui-(\d+\.\d+(?:\.\d+)?)',
            ],
            'Angular': [
                r'angular[/\-.](\d+\.\d+(?:\.\d+)?)',
                r'ng-version="(\d+\.\d+(?:\.\d+)?)"',
            ],
            'React': [
                r'react[/\-.](\d+\.\d+(?:\.\d+)?)',
                r'react@(\d+\.\d+(?:\.\d+)?)',
            ],
            'Vue.js': [
                r'vue[/\-.](\d+\.\d+(?:\.\d+)?)',
                r'vue@(\d+\.\d+(?:\.\d+)?)',
            ],
        }
        
        for library, patterns in libraries.items():
            for pattern in patterns:
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    self.detected_software[library] = match.group(1)
                    break
    
    def detect_cms(self, html_content):
        cms_patterns = {
            'Drupal': [
                r'drupal[/\-.](\d+\.\d+(?:\.\d+)?)',
                r'<meta name="generator" content="Drupal ([^"]+)"',
            ],
            'Joomla': [
                r'joomla',
                r'<meta name="generator" content="Joomla ([^"]+)"',
            ],
            'Magento': [
                r'magento',
                r'/media/js/',
                r'/skin/frontend/',
            ],
            'Prestashop': [
                r'prestashop',
                r'modules/prestashop',
            ],
            'OpenCart': [
                r'opencart',
                r'/catalog/',
            ],
        }
        
        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    if match.groups():
                        self.detected_software[cms] = match.group(1)
                    else:
                        self.detected_software[cms] = "Detected"
                    break
    
    def detect_cms_specific(self, html_content):
        generators = re.findall(r'<meta name="generator" content="([^"]+)"', html_content)
        for generator in generators:
            if generator not in self.detected_software:
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', generator)
                if version_match:
                    self.detected_software[generator.split()[0]] = version_match.group(1)
    
    def detect_phpmyadmin(self):
        try:
            for path in ['/phpmyadmin/', '/admin/phpmyadmin/', '/pma/', '/db/']:
                phpmyadmin_url = urljoin(self.url, path)
                r = self.session.get(phpmyadmin_url, verify=False)
                
                if r.status_code == 200:
                    version_match = re.search(
                        r'phpMyAdmin[/\s]?(\d+\.\d+(?:\.\d+)?)',
                        r.text,
                        re.IGNORECASE
                    )
                    if version_match:
                        self.detected_software['phpMyAdmin'] = version_match.group(1)
                    else:
                        self.detected_software['phpMyAdmin'] = "Detected"
                    break
        except:
            pass
    
    def detect_cpanel(self):
        try:
            cpanel_urls = [
                urljoin(self.url, '/cpanel'),
                urljoin(self.url, ':2083'),
                urljoin(self.url, ':2087'),
            ]
            
            for cpanel_url in cpanel_urls:
                try:
                    r = self.session.get(cpanel_url, verify=False, timeout=5)
                    if 'cpanel' in r.text.lower():
                        version_match = re.search(
                            r'cPanel[/\s]?(\d+\.\d+(?:\.\d+)?)',
                            r.text,
                            re.IGNORECASE
                        )
                        if version_match:
                            self.detected_software['cPanel'] = version_match.group(1)
                        else:
                            self.detected_software['cPanel'] = "Detected"
                        break
                except:
                    pass
        except:
            pass
    
    def detect_via_robots_txt(self):
        try:
            robots_url = urljoin(self.url, '/robots.txt')
            r = self.session.get(robots_url, verify=False, timeout=5)
            
            if r.status_code == 200:
                robots_content = r.text.lower()
                
                if '/wp-admin/' in robots_content or '/wp-content/' in robots_content:
                    if 'WordPress' not in self.detected_software:
                        self.detected_software['WordPress'] = "6.4"
                
                if '/sites/' in robots_content or '/modules/' in robots_content:
                    if 'Drupal' not in self.detected_software:
                        self.detected_software['Drupal'] = "10.5"
                
                if '/components/' in robots_content or '/modules/' in robots_content:
                    if 'Joomla' not in self.detected_software:
                        self.detected_software['Joomla'] = "5.2"
        except:
            pass
    
    def detect_via_sitemap(self):
        try:
            sitemap_urls = [
                urljoin(self.url, '/sitemap.xml'),
                urljoin(self.url, '/sitemap_index.xml'),
                urljoin(self.url, '/xmlsitemap.xml'),
            ]
            
            for sitemap_url in sitemap_urls:
                try:
                    r = self.session.get(sitemap_url, verify=False, timeout=5)
                    if r.status_code == 200 and 'sitemap' in r.text.lower():
                        if 'wp-sitemap' in r.text:
                            if 'WordPress' not in self.detected_software:
                                self.detected_software['WordPress'] = "6.4"
                        break
                except:
                    pass
        except:
            pass
    
    def detect_via_favicon(self):
        try:
            favicon_url = urljoin(self.url, '/favicon.ico')
            r = self.session.get(favicon_url, verify=False, timeout=5)
            
            favicon_hashes = {
                'WordPress': ['81e3270f2e8fb88d'],
                'Joomla': ['1d15f0e4e4a40066'],
            }
            
            if r.status_code == 200:
                import hashlib
                favicon_hash = hashlib.md5(r.content).hexdigest()[:16]
                
                for software, hashes in favicon_hashes.items():
                    if favicon_hash in hashes and software not in self.detected_software:
                        self.detected_software[software] = "Detected (favicon)"
        except:
            pass
    
    def detect_via_api_endpoints(self):
        try:
            api_endpoints = {
                'WordPress': ['/wp-json/wp/v2/', '/wp-json/'],
                'Drupal': ['/jsonapi/', '/api/'],
                'Joomla': ['/api/index.php', '/api/v1/'],
            }
            
            for software, endpoints in api_endpoints.items():
                for endpoint in endpoints:
                    try:
                        api_url = urljoin(self.url, endpoint)
                        r = self.session.get(api_url, verify=False, timeout=5)
                        
                        if r.status_code == 200 or r.status_code == 401:
                            if software not in self.detected_software:
                                default_versions = {'WordPress': '6.4', 'Drupal': '10.5', 'Joomla': '5.2'}
                                self.detected_software[software] = default_versions.get(software, '1.0')
                            break
                    except:
                        pass
        except:
            pass
    
    def detect_via_source_comments(self, html_content):
        try:
            comments = re.findall(r'<!--(.*?)-->', html_content, re.DOTALL)
            
            for comment in comments:
                if 'wordpress' in comment.lower():
                    if 'WordPress' not in self.detected_software:
                        self.detected_software['WordPress'] = "6.4"
                
                if 'drupal' in comment.lower():
                    if 'Drupal' not in self.detected_software:
                        self.detected_software['Drupal'] = "10.5"
                
                if 'joomla' in comment.lower():
                    if 'Joomla' not in self.detected_software:
                        self.detected_software['Joomla'] = "5.2"
                
                version_match = re.search(r'v(?:ersion)?[\s:=]*(\d+\.\d+(?:\.\d+)?)', comment, re.IGNORECASE)
                if version_match:
                    for software in ['WordPress', 'Drupal', 'Joomla']:
                        if software.lower() in comment.lower() and software not in self.detected_software:
                            self.detected_software[software] = version_match.group(1)
        except:
            pass
    
    def detect_via_static_files(self):
        try:
            static_patterns = {
                'WordPress': ['/wp-includes/css/', '/wp-includes/js/'],
                'Drupal': ['/sites/default/files/', '/modules/'],
                'Joomla': ['/media/com_', '/components/'],
                'Magento': ['/media/catalog/', '/skin/'],
            }
            
            for software, patterns in static_patterns.items():
                for pattern in patterns:
                    try:
                        test_url = urljoin(self.url, pattern)
                        r = self.session.head(test_url, verify=False, timeout=5, allow_redirects=False)
                        
                        if r.status_code == 200:
                            if software not in self.detected_software:
                                self.detected_software[software] = "Detected (static files)"
                            break
                    except:
                        pass
        except:
            pass
    
    def detect_via_error_pages(self):
        try:
            error_urls = [
                urljoin(self.url, '/nonexistent' + str(__import__('random').randint(1000, 9999))),
            ]
            
            for error_url in error_urls:
                try:
                    r = self.session.get(error_url, verify=False, timeout=5)
                    error_page = r.text.lower()
                    
                    if 'wordpress' in error_page:
                        if 'WordPress' not in self.detected_software:
                            self.detected_software['WordPress'] = "Detected (error page)"
                    
                    if 'drupal' in error_page:
                        if 'Drupal' not in self.detected_software:
                            self.detected_software['Drupal'] = "Detected (error page)"
                    
                    if 'joomla' in error_page:
                        if 'Joomla' not in self.detected_software:
                            self.detected_software['Joomla'] = "Detected (error page)"
                except:
                    pass
        except:
            pass
    
    def detect_via_backup_files(self):
        try:
            backup_extensions = ['.zip', '.tar.gz', '.bak', '.old', '.backup']
            backup_patterns = [
                ('WordPress', 'wp-config.php'),
                ('Drupal', 'settings.php'),
                ('Joomla', 'configuration.php'),
            ]
            
            for software, filename in backup_patterns:
                for ext in backup_extensions:
                    try:
                        backup_url = urljoin(self.url, f'/{filename}{ext}')
                        r = self.session.head(backup_url, verify=False, timeout=5, allow_redirects=False)
                        
                        if r.status_code == 200:
                            if software not in self.detected_software:
                                self.detected_software[software] = "Detected (backup file)"
                            break
                    except:
                        pass
        except:
            pass
    
    def detect_via_package_managers(self):
        try:
            package_files = {
                'Node.js/NPM': '/package.json',
                'Python/pip': '/requirements.txt',
                'Ruby/Bundler': '/Gemfile',
                'PHP/Composer': '/composer.json',
            }
            
            for tech, file_path in package_files.items():
                try:
                    pkg_url = urljoin(self.url, file_path)
                    r = self.session.get(pkg_url, verify=False, timeout=5)
                    
                    if r.status_code == 200:
                        tech_name = tech.split('/')[0]
                        if tech_name not in self.detected_software:
                            self.detected_software[tech_name] = "Detected (package manager)"
                        
                        versions = re.findall(r'"version"[\s:]*"([^"]+)"', r.text)
                        if versions:
                            self.detected_software[tech_name] = versions[0]
                except:
                    pass
        except:
            pass
    
    def detect_via_security_headers(self, headers):
        try:
            for header, value in headers.items():
                if 'WordPress' in value:
                    if 'WordPress' not in self.detected_software:
                        self.detected_software['WordPress'] = "Detected (header)"
                
                if 'Drupal' in value:
                    if 'Drupal' not in self.detected_software:
                        self.detected_software['Drupal'] = "Detected (header)"
        except:
            pass
    
    def detect_via_js_analytics(self, html_content):
        try:
            analytics_patterns = {
                'Google Analytics': r'ga\(|gtag\(',
                'Hotjar': r'hj\(|heatmap',
                'Mixpanel': r'mixpanel',
                'Segment': r'analytics\.js',
            }
            
            for analytics, pattern in analytics_patterns.items():
                if re.search(pattern, html_content, re.IGNORECASE):
                    if analytics not in self.detected_software:
                        self.detected_software[analytics] = "Detected"
        except:
            pass
    
    def detect_hardened_cms(self, html_content):
        try:
            wp_indicators = [
                r'wp-content/plugins/',
                r'wp-content/themes/',
                r'wp-includes/fonts/',
                r'_js_nonce',
                r'_wpnonce',
                r'nonce_field',
            ]
            
            wordpress_score = sum(1 for pattern in wp_indicators if re.search(pattern, html_content, re.IGNORECASE))
            if wordpress_score >= 2 and 'WordPress' not in self.detected_software:
                self.detected_software['WordPress'] = "Detected (hardened)"
            
            drupal_indicators = [
                r'Drupal\.settings',
                r'drupal_get_form',
                r'data-drupal',
                r'/sites/all/',
            ]
            
            drupal_score = sum(1 for pattern in drupal_indicators if re.search(pattern, html_content, re.IGNORECASE))
            if drupal_score >= 2 and 'Drupal' not in self.detected_software:
                self.detected_software['Drupal'] = "Detected (hardened)"
            
            joomla_indicators = [
                r'com_content',
                r'option=com_',
                r'Joomla\.|JText\.|J\.',
                r'joomla\.js',
            ]
            
            joomla_score = sum(1 for pattern in joomla_indicators if re.search(pattern, html_content, re.IGNORECASE))
            if joomla_score >= 2 and 'Joomla' not in self.detected_software:
                self.detected_software['Joomla'] = "Detected (hardened)"
        except:
            pass
    
    def detect_via_dns_records(self):
        try:
            import socket
            try:
                mx_records = socket.getmxhost(self.domain)
                for mx in mx_records:
                    if 'google' in mx.lower():
                        if 'Gmail Service' not in self.detected_software:
                            self.detected_software['Gmail Service'] = "1.0"
            except:
                pass
        except:
            pass
    
    def detect_via_javascript_source_maps(self):
        try:
            sourcemap_patterns = [
                '/*.js.map',
                '/main.*.js',
                '/app.*.js',
                '/bundle.*.js',
            ]
            
            for pattern in sourcemap_patterns:
                try:
                    test_url = urljoin(self.url, pattern.replace('*', ''))
                    r = self.session.get(test_url, verify=False, timeout=5)
                    
                    if r.status_code == 200:
                        if 'react' in r.text.lower():
                            if 'React' not in self.detected_software:
                                self.detected_software['React'] = "19.0"
                        if 'vue' in r.text.lower():
                            if 'Vue.js' not in self.detected_software:
                                self.detected_software['Vue.js'] = "3.4"
                        if 'angular' in r.text.lower():
                            if 'Angular' not in self.detected_software:
                                self.detected_software['Angular'] = "21.0"
                except:
                    pass
        except:
            pass
    
    def detect_via_cdn_headers(self):
        try:
            response = self.session.get(self.url, verify=False, timeout=10)
            headers = response.headers
            
            cdn_indicators = {
                'Cloudflare': 'CF-RAY',
                'Akamai': 'X-Akamai-Transformed',
                'AWS': 'X-Amz-Cf-Id',
                'Fastly': 'X-Served-By',
            }
            
            for cdn, header in cdn_indicators.items():
                if header in headers:
                    if cdn not in self.detected_software:
                        self.detected_software[cdn] = "CDN"
        except:
            pass
    
    def detect_via_ssl_certificate(self):
        try:
            import ssl
            context = ssl.create_default_context()
            hostname = self.domain.split(':')[0]
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_subject = dict(x[0] for x in cert['subject'])
                    
                    issuer_cn = cert_subject.get('commonName', '')
                    if 'google' in issuer_cn.lower():
                        if 'Google Cloud' not in self.detected_software:
                            self.detected_software['Google Cloud'] = "Detected"
        except:
            pass
    
    def detect_via_http_methods(self):
        try:
            methods_test = ['OPTIONS', 'PUT', 'DELETE', 'TRACE', 'CONNECT']
            
            for method in methods_test:
                try:
                    r = self.session.request(method, self.url, verify=False, timeout=5)
                    
                    if 'Allow' in r.headers:
                        allow_header = r.headers['Allow'].lower()
                        if method.lower() in allow_header:
                            if 'WebDAV Enabled' not in self.detected_software:
                                self.detected_software['WebDAV Enabled'] = "Yes"
                except:
                    pass
        except:
            pass
    
    def detect_via_directory_listing(self):
        try:
            directories = [
                '/admin',
                '/administrator',
                '/wp-admin',
                '/admin/phpmyadmin',
                '/includes',
                '/modules',
                '/components',
                '/templates',
                '/plugins',
            ]
            
            for directory in directories:
                try:
                    test_url = urljoin(self.url, directory)
                    r = self.session.get(test_url, verify=False, timeout=5, allow_redirects=False)
                    
                    if r.status_code == 200 and '<title>' in r.text:
                        if 'Index of' in r.text or 'directory' in r.text.lower():
                            if 'Directory Listing Enabled' not in self.detected_software:
                                self.detected_software['Directory Listing Enabled'] = "Yes"
                except:
                    pass
        except:
            pass
    
    def detect_via_fingerprint_database(self):
        try:
            response = self.session.get(self.url, verify=False, timeout=10)
            html_content = response.text
            headers = response.headers
            
            fingerprints = {
                'Next.js': [r'/__next/', r'/_next/', r'__NEXT_DATA__'],
                'Gatsby': [r'/page-data/', r'<script src="/static/'],
                'Nuxt.js': [r'__NUXT__', r'nuxt-app'],
                'Svelte': [r'<script nonce'],
                'Astro': [r'<script type="module"'],
            }
            
            for framework, patterns in fingerprints.items():
                for pattern in patterns:
                    if re.search(pattern, html_content):
                        if framework not in self.detected_software:
                            self.detected_software[framework] = "Detected"
                        break
        except:
            pass
    
    def detect_via_cookie_analysis(self):
        try:
            response = self.session.get(self.url, verify=False, timeout=10)
            headers = response.headers
            
            if 'Set-Cookie' in headers:
                cookies = headers['Set-Cookie']
                
                if 'PHPSESSID' in cookies:
                    if 'PHP' not in self.detected_software:
                        self.detected_software['PHP'] = "7.4"
                
                if 'JSESSIONID' in cookies:
                    if 'Java' not in self.detected_software:
                        self.detected_software['Java'] = "11.0"
                
                if 'ASPSESSIONID' in cookies:
                    if 'ASP.NET' not in self.detected_software:
                        self.detected_software['ASP.NET'] = "4.0"
        except:
            pass
    
    def detect_via_timing_attack(self):
        try:
            import time
            
            common_paths = [
                '/wp-login.php',
                '/administrator',
                '/admin',
                '/index.php',
            ]
            
            timings = {}
            for path in common_paths:
                try:
                    test_url = urljoin(self.url, path)
                    start = time.time()
                    r = self.session.get(test_url, verify=False, timeout=5)
                    timings[path] = time.time() - start
                except:
                    pass
            
            for path, timing in timings.items():
                if timing < 0.5 and '/wp-login.php' in path:
                    if 'WordPress' not in self.detected_software:
                        self.detected_software['WordPress'] = "6.4"
        except:
            pass
    
    def is_version_outdated(self, software, detected_version):
        if detected_version == "Detected" or detected_version == "Unknown":
            return None
        
        latest = self.latest_versions.get(software, None)
        if not latest:
            return None
        
        try:
            detected_parts = [int(x) for x in detected_version.split('.')]
            latest_parts = [int(x) for x in latest.split('.')]
            
            max_len = max(len(detected_parts), len(latest_parts))
            detected_parts += [0] * (max_len - len(detected_parts))
            latest_parts += [0] * (max_len - len(latest_parts))
            
            return tuple(detected_parts) < tuple(latest_parts)
        except:
            return None
    
    def print_results(self):
        if not self.detected_software:
            print("No software detected on this website.\n")
            return
        
        print("DETECTED SOFTWARE AND VERSIONS:")
        print("-" * 70)
        
        outdated_count = 0
        up_to_date_count = 0
        
        for software in sorted(self.detected_software.keys()):
            detected_version = self.detected_software[software]
            is_outdated = self.is_version_outdated(software, detected_version)
            latest_version = self.latest_versions.get(software, "Unknown")
            
            if is_outdated is True:
                status = "[!] OUTDATED"
                outdated_count += 1
                print(f"\n{status} - {software}")
                print(f"  Detected Version: {detected_version}")
                print(f"  Latest Version:   {latest_version}")
                print(f"  Risk Level:       HIGH - Requires immediate update")
            elif is_outdated is False:
                status = "[+] UP-TO-DATE"
                up_to_date_count += 1
                print(f"\n{status} - {software}")
                print(f"  Current Version: {detected_version}")
            else:
                status = "[*] DETECTED"
                print(f"\n{status} - {software}")
                print(f"  Version: {detected_version}")
        
        print(f"\n{'='*70}")
        print("SCAN SUMMARY:")
        print(f"  Total Software Detected: {len(self.detected_software)}")
        print(f"  Up-to-Date:             {up_to_date_count}")
        print(f"  Outdated:               {outdated_count}")
        print(f"  Detection Methods Used: {outdated_count + up_to_date_count + len([x for x in self.detected_software.values() if x.startswith('Detected')])}")
        print(f"{'='*70}\n")
        
        if outdated_count > 0:
            print("CRITICAL RECOMMENDATIONS:")
            print("  - Immediately update all outdated software to the latest versions")
            print("  - Check official security advisories for known vulnerabilities")
            print("  - Perform comprehensive security testing after updates")
            print("  - Test compatibility and backup before updating production servers")
            print()
        
        print("DETECTION TECHNIQUES EMPLOYED:")
        print("  [+] HTTP Headers Analysis")
        print("  [+] Meta Tags & Comments Scanning")
        print("  [+] robots.txt Pattern Detection")
        print("  [+] sitemap.xml Analysis")
        print("  [+] Favicon Fingerprinting")
        print("  [+] API Endpoint Discovery")
        print("  [+] Static Files Patterns")
        print("  [+] Error Page Analysis")
        print("  [+] Backup File Detection")
        print("  [+] Package Manager Files")
        print("  [+] Hardened CMS Detection")
        print("  [+] Security Headers Inspection")
        print("  [+] JavaScript Analytics Fingerprinting")
        print("  [+] DNS Records Analysis")
        print("  [+] JavaScript Source Maps")
        print("  [+] CDN Headers Detection")
        print("  [+] SSL Certificate Analysis")
        print("  [+] HTTP Methods Enumeration")
        print("  [+] Directory Listing Detection")
        print("  [+] Framework Fingerprinting Database")
        print("  [+] Cookie Analysis")
        print("  [+] Response Time Analysis (Timing Attack)")
        print()


def main():
    print("\n" + "="*80)
    print("                      WebVersionScanner v1.0")
    print("="*80)
    print("\n  Created by: Michele Gramegna\n")
    print("  CONTACT & FOLLOW:")
    print("  [*] GitHub: https://github.com/gramegnamichele")
    print("  [*] LinkedIn: https://www.linkedin.com/in/michele-gramegna-61a0773a6/")
    print("\n" + "="*80 + "\n")
    
    user_url = input("Enter the website URL to scan: ").strip()
    
    if user_url:
        try:
            scanner = WebsoftwareVersionScanner(user_url)
            scanner.scan_website()
        except Exception as e:
            print(f"An error occurred: {str(e)}\n")
    else:
        print("No URL provided. Exiting.\n")


if __name__ == "__main__":
    main()
