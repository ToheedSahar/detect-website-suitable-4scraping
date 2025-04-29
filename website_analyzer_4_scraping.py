#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Website Scraping Analyzer
-------------------------
A comprehensive tool to analyze websites and determine the best scraping approach.
This tool evaluates 28 key aspects of a website and saves the results to a text file.

Requirements:
- Python 3.8+
- See requirements.txt for dependencies
"""
import sys
import os
import re
import json
import time
import random
import socket
import logging
import argparse
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Union, Optional, Any

# HTTP and network libraries
import requests
import cloudscraper
import whois
import tldextract
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

# HTML and parsing libraries
from bs4 import BeautifulSoup
from lxml import etree, html

# Browser automation
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException, 
    WebDriverException,
    NoSuchElementException
)
from webdriver_manager.chrome import ChromeDriverManager

# Progress visualization
from tqdm import tqdm

# Optional: For technology detection (if wappalyzer is installed)
try:
    from Wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False

# Optional: For Playwright (if installed)
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Constants
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
]

KNOWN_FRAMEWORKS = {
    'react': ['react', 'reactjs', 'react-dom'],
    'angular': ['angular', 'ng-', 'ngIf', 'ngFor'],
    'vue': ['vue', 'vue.js', 'v-if', 'v-for'],
    'jquery': ['jquery', 'jQuery'],
    'bootstrap': ['bootstrap'],
    'tailwind': ['tailwind', 'tw-'],
    'nextjs': ['next', '__NEXT_DATA__'],
    'nuxt': ['nuxt', '__NUXT__'],
    'svelte': ['svelte', '__SVELTE__'],
    'ember': ['ember', 'emberjs'],
    'gatsby': ['gatsby', '__gatsby'],
    'wordpress': ['wp-content', 'wp-includes'],
    'drupal': ['drupal', 'Drupal'],
    'joomla': ['joomla', 'Joomla'],
    'shopify': ['shopify'],
    'magento': ['magento'],
    'wix': ['wix']
}

ANTI_BOT_SIGNATURES = {
    'cloudflare': ['cloudflare', 'cf-ray', 'cf_clearance'],
    'imperva': ['incapsula', '_incapsula', 'visid_incap'],
    'akamai': ['akamai', 'akam_'],
    'distil': ['distil', '_distillery'],
    'datadome': ['datadome', 'datadome_'],
    'recaptcha': ['recaptcha', 'g-recaptcha'],
    'hcaptcha': ['hcaptcha', 'h-captcha'],
    'perimeter_x': ['px-captcha', '_px', '_pxAction'],
    'botd': ['botd', 'bot-d'],
    'kasada': ['kasada', 'k-']
}

LOGIN_INDICATORS = [
    'login', 'sign in', 'signin', 'log in', 'authorize', 'authentication',
    'username', 'password', 'email', 'forgot password', 'remember me'
]

# Core classes for website analysis
class WebsiteAnalyzer:
    """Main class for analyzing a website and determining scraping approach."""
    
    def __init__(self, url: str, use_selenium: bool = True, use_playwright: bool = False,
                 timeout: int = 30, headers: Optional[Dict] = None, verbose: bool = False):
        """
        Initialize the website analyzer.
        
        Args:
            url: Target website URL
            use_selenium: Whether to use Selenium for JavaScript rendering
            use_playwright: Whether to use Playwright for JavaScript rendering
            timeout: Request timeout in seconds
            headers: Custom headers for requests
            verbose: Whether to display detailed logging information
        """
        self.url = self._normalize_url(url)
        self.domain = self._extract_domain(url)
        self.timeout = timeout
        self.verbose = verbose
        self.use_selenium = use_selenium
        self.use_playwright = use_playwright and PLAYWRIGHT_AVAILABLE
        
        # Initialize headers with random user agent
        self.headers = headers or {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        
        # Initialize browser drivers
        self.selenium_driver = None
        self.playwright_browser = None
        self.playwright_context = None
        self.playwright_page = None
        
        # Data containers
        self.initial_response = None
        self.selenium_content = None
        self.playwright_content = None
        self.soup = None
        self.selenium_soup = None
        self.playwright_soup = None
        self.results = {}
        
        # Features
        self.js_links = []
        self.forms = []
        self.api_endpoints = []
        self.resource_urls = []
        
        if self.verbose:
            logger.setLevel(logging.DEBUG)
        
        logger.info(f"Initialized analyzer for {self.url}")
    
    def _normalize_url(self, url: str) -> str:
        """Ensure URL has proper scheme."""
        if not url.startswith(('http://', 'https://')):
            return f"https://{url}"
        return url
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def _get_output_filename(self) -> str:
        """Generate output filename based on domain."""
        return f"{self.domain}_limitations.txt"
    
    def _setup_selenium(self) -> None:
        """Set up Selenium WebDriver with Chrome."""
        if self.selenium_driver:
            return
            
        logger.info("Setting up Selenium with Chrome...")
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument(f"user-agent={self.headers['User-Agent']}")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-notifications")
        options.add_argument("--disable-popup-blocking")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)
        
        service = Service(ChromeDriverManager().install())
        self.selenium_driver = webdriver.Chrome(service=service, options=options)
        self.selenium_driver.set_page_load_timeout(self.timeout)
    
    def _setup_playwright(self) -> None:
        """Set up Playwright with Chromium."""
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("Playwright is not installed. Skipping Playwright analysis.")
            return
            
        if self.playwright_browser:
            return
            
        logger.info("Setting up Playwright with Chromium...")
        playwright = sync_playwright().start()
        self.playwright = playwright
        self.playwright_browser = playwright.chromium.launch(headless=True)
        self.playwright_context = self.playwright_browser.new_context(
            user_agent=self.headers['User-Agent'],
            viewport={"width": 1920, "height": 1080}
        )
        self.playwright_page = self.playwright_context.new_page()
        self.playwright_page.set_default_timeout(self.timeout * 1000)
    
    def _cleanup_selenium(self) -> None:
        """Clean up Selenium resources."""
        if self.selenium_driver:
            logger.debug("Cleaning up Selenium...")
            try:
                self.selenium_driver.quit()
            except Exception as e:
                logger.error(f"Error closing Selenium: {e}")
            self.selenium_driver = None
    
    def _cleanup_playwright(self) -> None:
        """Clean up Playwright resources."""
        if hasattr(self, 'playwright') and self.playwright:
            logger.debug("Cleaning up Playwright...")
            try:
                if self.playwright_page:
                    self.playwright_page.close()
                if self.playwright_context:
                    self.playwright_context.close()
                if self.playwright_browser:
                    self.playwright_browser.close()
                self.playwright.stop()
            except Exception as e:
                logger.error(f"Error closing Playwright: {e}")
            self.playwright_browser = None
            self.playwright_context = None
            self.playwright_page = None
            self.playwright = None
    
    def _make_request(self) -> Tuple[requests.Response, bool]:
        """Make an initial HTTP request to the target URL."""
        logger.info(f"Making initial request to {self.url}")
        try:
            # First try with standard requests
            response = requests.get(
                self.url, 
                headers=self.headers, 
                timeout=self.timeout,
                verify=False  # Skip SSL verification for problematic sites
            )
            return response, False
        except RequestException as e:
            logger.warning(f"Standard request failed: {e}. Trying cloudscraper...")
            try:
                # Try with cloudscraper for anti-bot bypassing
                scraper = cloudscraper.create_scraper(
                    browser={
                        'browser': 'chrome',
                        'platform': 'windows',
                        'desktop': True
                    }
                )
                response = scraper.get(
                    self.url,
                    timeout=self.timeout
                )
                return response, True
            except Exception as e2:
                logger.error(f"Both request methods failed: {e2}")
                # Return a dummy response
                dummy_response = requests.Response()
                dummy_response.status_code = 0
                dummy_response._content = b""
                dummy_response.url = self.url
                return dummy_response, False
    
    def _fetch_with_selenium(self) -> str:
        """Fetch page content using Selenium."""
        if not self.use_selenium:
            return ""
            
        logger.info("Fetching content with Selenium...")
        try:
            self._setup_selenium()
            self.selenium_driver.get(self.url)
            
            # Wait for page to load (body element present)
            WebDriverWait(self.selenium_driver, self.timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Allow extra time for JavaScript to execute
            time.sleep(3)
            
            # Get page source
            content = self.selenium_driver.page_source
            
            # Check for login indicators
            login_found = False
            for indicator in LOGIN_INDICATORS:
                if indicator in content.lower():
                    login_found = True
                    logger.info(f"Login indicator '{indicator}' found")
                    break
            
            # Check for forms and inputs
            try:
                forms = self.selenium_driver.find_elements(By.TAG_NAME, "form")
                self.forms = [form.get_attribute("outerHTML") for form in forms if form]
                logger.debug(f"Found {len(self.forms)} forms")
            except Exception as e:
                logger.error(f"Error finding forms: {e}")
            
            # Check for JavaScript links
            try:
                js_links = self.selenium_driver.find_elements(
                    By.XPATH, "//a[starts-with(@href, 'javascript:')]"
                )
                self.js_links = [link.get_attribute("outerHTML") for link in js_links if link]
                logger.debug(f"Found {len(self.js_links)} JavaScript links")
            except Exception as e:
                logger.error(f"Error finding JS links: {e}")
            
            return content
        except Exception as e:
            logger.error(f"Selenium error: {e}")
            return ""
    
    def _fetch_with_playwright(self) -> str:
        """Fetch page content using Playwright."""
        if not self.use_playwright or not PLAYWRIGHT_AVAILABLE:
            return ""
            
        logger.info("Fetching content with Playwright...")
        try:
            self._setup_playwright()
            
            # Go to URL
            self.playwright_page.goto(self.url, wait_until="networkidle")
            
            # Wait extra time for JavaScript execution
            self.playwright_page.wait_for_timeout(3000)
            
            # Get page content
            content = self.playwright_page.content()
            
            # Check for network requests to find API endpoints
            api_endpoints = []
            for request in self.playwright_page.context.pages[0].request.all():
                url = request.url
                if 'api' in url or 'graphql' in url or 'json' in url:
                    api_endpoints.append(url)
            
            self.api_endpoints = list(set(api_endpoints))
            logger.debug(f"Found {len(self.api_endpoints)} potential API endpoints")
            
            return content
        except Exception as e:
            logger.error(f"Playwright error: {e}")
            return ""
    
    def _analyze_robots_txt(self) -> Dict[str, Any]:
        """Analyze robots.txt file."""
        logger.info("Analyzing robots.txt...")
        robots_url = urllib.parse.urljoin(self.url, "/robots.txt")
        results = {
            "exists": False,
            "allows_scraping": True,
            "disallowed_paths": [],
            "sitemap_paths": []
        }
        
        try:
            response = requests.get(
                robots_url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                results["exists"] = True
                content = response.text
                
                # Check for disallowed paths
                disallowed = re.findall(r'Disallow:\s*([^\n]+)', content, re.IGNORECASE)
                results["disallowed_paths"] = [p.strip() for p in disallowed if p.strip()]
                
                # Check for sitemaps
                sitemaps = re.findall(r'Sitemap:\s*([^\n]+)', content, re.IGNORECASE)
                results["sitemap_paths"] = [s.strip() for s in sitemaps if s.strip()]
                
                # Check if root path is disallowed
                if any(p.strip() in ('/', '*') for p in disallowed):
                    results["allows_scraping"] = False
                
                logger.debug(f"Found {len(results['disallowed_paths'])} disallowed paths")
                logger.debug(f"Found {len(results['sitemap_paths'])} sitemaps")
            else:
                logger.debug(f"No robots.txt found (status code: {response.status_code})")
        except Exception as e:
            logger.error(f"Error analyzing robots.txt: {e}")
        
        return results
    
    def _detect_cloudflare(self, content: str, headers: Dict) -> bool:
        """Detect if Cloudflare protection is present."""
        cf_indicators = [
            'cloudflare' in content.lower(),
            any('cf-' in key.lower() for key in headers.keys()),
            'cf-ray' in headers.keys(),
            'cf-cache-status' in headers.keys(),
            'DDoS protection by Cloudflare' in content,
            'cdn-cgi/challenge-platform' in content,
            '__cf_bm' in content
        ]
        return any(cf_indicators)
    
    def _detect_frameworks(self, content: str) -> List[str]:
        """Detect web frameworks used by the site."""
        detected = []
        
        # Try to detect from HTML content
        for framework, signatures in KNOWN_FRAMEWORKS.items():
            for signature in signatures:
                if signature.lower() in content.lower():
                    detected.append(framework)
                    break
        
        # Look for specific meta tags
        soup = BeautifulSoup(content, 'html.parser')
        meta_generators = soup.find_all('meta', attrs={'name': 'generator'})
        
        for meta in meta_generators:
            content = meta.get('content', '').lower()
            if content:
                for framework in KNOWN_FRAMEWORKS:
                    if framework in content:
                        detected.append(framework)
        
        # Look for typical webpack signatures
        if '__NEXT_DATA__' in content:
            detected.append('nextjs')
        if 'webpackJsonp' in content:
            detected.append('webpack')
            
        # Use wappalyzer if available
        if WAPPALYZER_AVAILABLE:
            try:
                wappalyzer = Wappalyzer.latest()
                webpage = WebPage.new_from_url(self.url)
                wappalyzer_results = wappalyzer.analyze_with_versions(webpage)
                
                if 'JavaScript Frameworks' in wappalyzer_results:
                    for framework in wappalyzer_results['JavaScript Frameworks']:
                        detected.append(framework.lower())
                
                if 'Web Frameworks' in wappalyzer_results:
                    for framework in wappalyzer_results['Web Frameworks']:
                        detected.append(framework.lower())
            except Exception as e:
                logger.error(f"Wappalyzer error: {e}")
        
        # Remove duplicates while preserving order
        return list(dict.fromkeys(detected))
    
    def _detect_anti_bot(self, content: str, headers: Dict) -> List[str]:
        """Detect anti-bot protections."""
        detected = []
        
        # Check content for known anti-bot signatures
        for protection, signatures in ANTI_BOT_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in content.lower():
                    detected.append(protection)
                    break
        
        # Check for Cloudflare specifically 
        if self._detect_cloudflare(content, headers):
            detected.append('cloudflare')
            
        # Check for CAPTCHA presence
        captcha_indicators = [
            'captcha' in content.lower(),
            'recaptcha' in content.lower(),
            'hcaptcha' in content.lower(),
            'g-recaptcha' in content.lower(),
            'h-captcha' in content.lower(),
        ]
        if any(captcha_indicators):
            detected.append('captcha')
            
        # Remove duplicates while preserving order
        return list(dict.fromkeys(detected))
    
    def _detect_login_requirement(self, content: str) -> bool:
        """Detect if login is required."""
        # Check for login indicators in content
        content_lower = content.lower()
        for indicator in LOGIN_INDICATORS:
            if indicator.lower() in content_lower:
                logger.debug(f"Login indicator found: {indicator}")
                return True
                
        # Look for login forms
        soup = BeautifulSoup(content, 'html.parser')
        
        # Check for forms with password fields
        password_fields = soup.find_all('input', attrs={'type': 'password'})
        if password_fields:
            logger.debug("Password field found in form")
            return True
            
        # Check for login buttons or links
        login_buttons = soup.find_all(['a', 'button'], text=re.compile(r'log.?in|sign.?in', re.I))
        if login_buttons:
            logger.debug("Login button found")
            return True
            
        return False
    
    def _detect_javascript_dependency(self, static_content: str, dynamic_content: str) -> Tuple[bool, float]:
        """
        Detect if the site depends on JavaScript for content rendering.
        
        Returns:
            Tuple[bool, float]: (is_js_dependent, difference_percentage)
        """
        if not static_content or not dynamic_content:
            return False, 0.0
            
        # Clean up the content to remove whitespace
        static_clean = re.sub(r'\s+', ' ', static_content).strip()
        dynamic_clean = re.sub(r'\s+', ' ', dynamic_content).strip()
        
        # Calculate length difference
        static_len = len(static_clean)
        dynamic_len = len(dynamic_clean)
        
        # Avoid division by zero
        if static_len == 0:
            return True, 1.0
            
        difference = abs(dynamic_len - static_len) / static_len
        
        # If dynamic content is significantly longer, site likely uses JS
        is_dependent = difference > 0.2  # More than 20% difference
        
        logger.debug(f"JS dependency analysis: static={static_len}, dynamic={dynamic_len}, diff={difference:.2f}")
        
        return is_dependent, difference
    
    def _detect_pagination(self, content: str) -> Dict[str, Any]:
        """Detect pagination methods."""
        soup = BeautifulSoup(content, 'html.parser')
        results = {
            "has_pagination": False,
            "pagination_type": "none",
            "pagination_details": {}
        }
        
        # Check for numbered pagination
        pagination_elements = soup.find_all(['div', 'nav', 'ul'], class_=re.compile(r'pag|pagination', re.I))
        if pagination_elements:
            results["has_pagination"] = True
            results["pagination_type"] = "numbered"
            
            # Look for page numbers
            page_links = []
            for element in pagination_elements:
                links = element.find_all('a')
                for link in links:
                    href = link.get('href', '')
                    text = link.text.strip()
                    if href and text and (text.isdigit() or text in ['›', '»', '‹', '«', 'next', 'prev']):
                        page_links.append((text, href))
            
            results["pagination_details"]["links"] = page_links[:10]  # Limit to 10 examples
        
        # Check for "Load More" button
        load_more_buttons = soup.find_all(['button', 'a'], text=re.compile(r'load.?more|show.?more', re.I))
        if load_more_buttons:
            results["has_pagination"] = True
            results["pagination_type"] = "load_more"
            
            button_details = []
            for button in load_more_buttons:
                button_text = button.text.strip()
                button_classes = button.get('class', [])
                button_id = button.get('id', '')
                button_details.append({
                    "text": button_text,
                    "classes": button_classes,
                    "id": button_id
                })
            
            results["pagination_details"]["buttons"] = button_details
        
        # Check for infinite scroll indicators (data attributes, loading spinners)
        infinite_indicators = soup.find_all(attrs={"data-infinite-scroll": True})
        if not infinite_indicators:
            infinite_indicators = soup.find_all(attrs={"data-infinite": True})
        if not infinite_indicators:
            infinite_indicators = soup.find_all(class_=re.compile(r'infinite|endless', re.I))
            
        if infinite_indicators:
            results["has_pagination"] = True
            results["pagination_type"] = "infinite_scroll"
            
        return results
    
    def _detect_rate_limits(self, headers: Dict) -> Dict[str, Any]:
        """Detect rate limiting from response headers."""
        rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'Retry-After',
            'X-Rate-Limit',
            'RateLimit-Limit',
            'RateLimit-Remaining',
            'RateLimit-Reset'
        ]
        
        results = {
            "has_rate_limits": False,
            "rate_limit_headers": {}
        }
        
        for header in rate_limit_headers:
            for key in headers:
                if header.lower() == key.lower():
                    results["has_rate_limits"] = True
                    results["rate_limit_headers"][key] = headers[key]
        
        return results
    
    def _check_api_endpoints(self, content: str) -> List[str]:
        """Check for potential API endpoints."""
        # Look for API URLs in JavaScript
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'["\'](https?://api\.[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
            r'["\'](https?://[^"\']+/graphql[^"\']*)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](https?://[^"\']+/rest/[^"\']+)["\']'
        ]
        
        endpoints = []
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if match.startswith('/'):
                    # Convert relative URL to absolute
                    full_url = urllib.parse.urljoin(self.url, match)
                    endpoints.append(full_url)
                else:
                    endpoints.append(match)
        
        # Remove duplicates while preserving order
        return list(dict.fromkeys(endpoints))
    
    def run_analysis(self) -> Dict[str, Any]:
        """
        Run the complete website analysis.
        
        Returns:
            Dict containing analysis results
        """
        logger.info(f"Starting analysis for {self.url}")
        
        try:
            # Step 1: Make initial HTTP request
            self.initial_response, used_cloudscraper = self._make_request()
            
            if self.initial_response.status_code == 0:
                logger.error("Failed to make initial request")
                return {"error": "Failed to make initial request to the website"}
                
            initial_content = self.initial_response.text
            self.soup = BeautifulSoup(initial_content, 'html.parser')
            
            # Step 2: Fetch with Selenium (if enabled)
            selenium_content = ""
            if self.use_selenium:
                selenium_content = self._fetch_with_selenium()
                if selenium_content:
                    self.selenium_content = selenium_content
                    self.selenium_soup = BeautifulSoup(selenium_content, 'html.parser')
            
            # Step 3: Fetch with Playwright (if enabled)
            playwright_content = ""
            if self.use_playwright and PLAYWRIGHT_AVAILABLE:
                playwright_content = self._fetch_with_playwright()
                if playwright_content:
                    self.playwright_content = playwright_content
                    self.playwright_soup = BeautifulSoup(playwright_content, 'html.parser')
            
            # Choose the best content source for analysis
            analysis_content = self.playwright_content or self.selenium_content or initial_content
            self.analysis_content = analysis_content
            
            # Step 4: Analyze website
            robots_txt = self._analyze_robots_txt()
            frameworks = self._detect_frameworks(analysis_content)
            anti_bot = self._detect_anti_bot(analysis_content, self.initial_response.headers)
            login_required = self._detect_login_requirement(analysis_content)
            js_dependent, js_difference = self._detect_javascript_dependency(initial_content, analysis_content)
            pagination = self._detect_pagination(analysis_content)
            rate_limits = self._detect_rate_limits(self.initial_response.headers)
            
            # Detect API endpoints
            api_endpoints = self._check_api_endpoints(analysis_content)
            api_endpoints.extend(self.api_endpoints)
            api_endpoints = list(dict.fromkeys(api_endpoints))
            
            # Compile results
            self.results = {
                "url": self.url,
                "domain": self.domain,
                "analysis_timestamp": datetime.now().isoformat(),
                "http_status": self.initial_response.status_code,
                "website_structure": {
                    "is_static": not js_dependent,
                    "is_dynamic": js_dependent,
                    "js_dependency_score": js_difference,
                    "content_difference": f"{js_difference:.2%}",
                    "frameworks_detected": frameworks,
                    "anti_bot_protection": anti_bot,
                    "uses_cloudflare": self._detect_cloudflare(analysis_content, self.initial_response.headers),
                },
                "authentication": {
                    "login_required": login_required,
                    "login_indicators_found": any(indicator in analysis_content.lower() for indicator in LOGIN_INDICATORS),
                    "forms_found": len(self.forms) > 0,
                },
                "data_accessibility": {
                    "pagination": pagination,
                    "api_endpoints_found": len(api_endpoints) > 0,
                    "api_endpoints": api_endpoints[:10],  # Limit to 10 examples
                    "js_links_found": len(self.js_links) > 0,
                    "js_links_count": len(self.js_links),
                },
                "legal_restrictions": {
                    "robots_txt": robots_txt,
                    "rate_limits": rate_limits,
                },
                "technical_requirements": {
                    "requires_javascript": js_dependent,
                    "cloudflare_bypass_needed": "cloudflare" in anti_bot,
                    "captcha_detected": "captcha" in anti_bot or "recaptcha" in anti_bot,
                }
            }
            
            logger.info("Analysis completed successfully")
            return self.results
            
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {"error": str(e)}
        finally:
            # Clean up resources
            self._cleanup_selenium()
            self._cleanup_playwright()
    
    def save_results(self, output_file: Optional[str] = None) -> str:
        """
        Save analysis results to a text file.
        
        Args:
            output_file: Optional custom output filename
            
        Returns:
            Path to the saved file
        """
        if not self.results:
            logger.error("No analysis results to save")
            return ""
            
        filename = output_file or self._get_output_filename()
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"# Website Scraping Analysis for {self.url}\n")
                f.write(f"# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Website Structure and Technology
                f.write("## Website Structure and Technology\n")
                f.write("1. Is the website static or dynamic (JavaScript-heavy)? ")
                f.write("Dynamic (JavaScript-heavy)" if self.results["website_structure"]["is_dynamic"] else "Static")
                f.write(f" - Content difference: {self.results['website_structure']['content_difference']}\n")
                
                f.write("2. Does the content load asynchronously or require user interaction to appear? ")
                f.write("Yes" if self.results["website_structure"]["is_dynamic"] else "No")
                if self.results["website_structure"]["js_dependency_score"] > 0.5:
                    f.write(" - Heavy JS dependency detected\n")
                else:
                    f.write("\n")
                
                f.write("3. What frameworks is the site built with (React, Angular, etc.)? ")
                if self.results["website_structure"]["frameworks_detected"]:
                    f.write(", ".join(self.results["website_structure"]["frameworks_detected"]))
                else:
                    f.write("No specific frameworks detected")
                f.write("\n")
                
                f.write("4. Are there anti-bot protections like CloudFlare, Imperva, or similar? ")
                if self.results["website_structure"]["anti_bot_protection"]:
                    f.write("Yes: " + ", ".join(self.results["website_structure"]["anti_bot_protection"]))
                else:
                    f.write("No anti-bot protections detected")
                f.write("\n")
                
                # Authentication Requirements
                f.write("\n## Authentication Requirements\n")
                f.write("5. Is login required to access the target data? ")
                f.write("Yes" if self.results["authentication"]["login_required"] else "No or unable to determine")
                f.write("\n")
                
                f.write("6. Does the site use session cookies, tokens, or other authentication mechanisms? ")
                if self.results["authentication"]["login_required"]:
                    f.write("Yes, authentication mechanisms are present")
                else:
                    f.write("No obvious authentication mechanisms detected")
                f.write("\n")
                
                f.write("7. Are there CAPTCHAs or other human verification steps? ")
                f.write("Yes" if self.results["technical_requirements"]["captcha_detected"] else "No")
                f.write("\n")
                
                # Data Volume and Accessibility
                f.write("\n## Data Volume and Accessibility\n")
                f.write("8. How much data needs to be extracted? Unable to determine automatically\n")
                
                f.write("9. Is pagination implemented? If so, how? ")
                if self.results["data_accessibility"]["pagination"]["has_pagination"]:
                    pagination_type = self.results["data_accessibility"]["pagination"]["pagination_type"]
                    f.write(f"Yes, using {pagination_type} pagination")
                else:
                    f.write("No pagination detected")
                f.write("\n")
                
                f.write("10. Is the data structured consistently across pages? Unable to determine automatically\n")
                
                f.write("11. Are there API endpoints that could be accessed directly instead of scraping the frontend? ")
                if self.results["data_accessibility"]["api_endpoints_found"]:
                    f.write(f"Yes, {len(self.results['data_accessibility']['api_endpoints'])} potential API endpoints found")
                    if self.results["data_accessibility"]["api_endpoints"]:
                        f.write("\n    Examples:")
                        for endpoint in self.results["data_accessibility"]["api_endpoints"]:
                            f.write(f"\n    - {endpoint}")
                else:
                    f.write("No obvious API endpoints detected")
                f.write("\n")
                
                # Legal and Ethical Considerations
                f.write("\n## Legal and Ethical Considerations\n")
                f.write("12. Does the website have a robots.txt file, and what does it allow/disallow? ")
                if self.results["legal_restrictions"]["robots_txt"]["exists"]:
                    if self.results["legal_restrictions"]["robots_txt"]["allows_scraping"]:
                        f.write("Yes, and it doesn't explicitly forbid scraping the target URL")
                    else:
                        f.write("Yes, and it DISALLOWS scraping the target URL or all URLs")
                    
                    if self.results["legal_restrictions"]["robots_txt"]["disallowed_paths"]:
                        f.write("\n    Disallowed paths:")
                        for path in self.results["legal_restrictions"]["robots_txt"]["disallowed_paths"][:5]:
                            f.write(f"\n    - {path}")
                        if len(self.results["legal_restrictions"]["robots_txt"]["disallowed_paths"]) > 5:
                            f.write(f"\n    - ...and {len(self.results['legal_restrictions']['robots_txt']['disallowed_paths']) - 5} more")
                else:
                    f.write("No robots.txt file found")
                f.write("\n")
                
                f.write("13. Are there rate limits specified in the terms of service? ")
                if self.results["legal_restrictions"]["rate_limits"]["has_rate_limits"]:
                    f.write("Yes, rate limits detected in HTTP headers")
                    for header, value in self.results["legal_restrictions"]["rate_limits"]["rate_limit_headers"].items():
                        f.write(f"\n    - {header}: {value}")
                else:
                    f.write("No explicit rate limits detected in headers (check Terms of Service manually)")
                f.write("\n")
                
                f.write("14. Is the data public or proprietary? Unable to determine automatically\n")
                
                f.write("15. Will your scraping activity significantly impact site performance? ")
                f.write("Unable to determine automatically - depends on scraping implementation\n")
                
                # Technical Requirements
                f.write("\n## Technical Requirements\n")
                f.write("16. What selectors should be used to target the data (CSS, XPath)? ")
                f.write("Unable to determine automatically - requires specific data inspection\n")
                
                f.write("17. Does the site use iframes or shadow DOM to encapsulate content? ")
                if self.analysis_content and ("iframe" in self.analysis_content.lower() or "shadowroot" in self.analysis_content.lower()):

                    f.write("Yes, iframes or shadow DOM elements detected")
                else:
                    f.write("No obvious iframes or shadow DOM detected")
                f.write("\n")
                
                f.write("18. Are there any redirects or interstitial pages? ")
                initial_url = self.url
                final_url = self.initial_response.url
                if initial_url != final_url:
                    f.write(f"Yes, redirected from {initial_url} to {final_url}")
                else:
                    f.write("No redirects detected during initial request")
                f.write("\n")
                
                f.write("19. Does the site implement fingerprinting to identify scrapers? ")
                fingerprinting_indicators = []
                if self.analysis_content:
                    fingerprinting_indicators = [
                        "fingerprint" in self.analysis_content.lower(),
                        ("canvas" in self.analysis_content.lower() and "toDataURL" in self.analysis_content.lower()),
                        "navigator.userAgent" in self.analysis_content,
                        "navigator.plugins" in self.analysis_content,
                        "navigator.mimeTypes" in self.analysis_content
                    ]
                if any(fingerprinting_indicators):
                    f.write("Possibly - fingerprinting indicators detected")
                else:
                    f.write("No obvious fingerprinting detected")
                f.write("\n")
                
                f.write("20. How often does the website structure change? Unable to determine automatically\n")
                
                # Output and Processing Needs
                f.write("\n## Output and Processing Needs\n")
                f.write("21. What format should the extracted data be stored in? ")
                f.write("Depends on your specific needs and the data structure\n")
                
                f.write("22. Is concurrent scraping required for efficiency? ")
                f.write("Depends on data volume and time constraints\n")
                
                f.write("23. Do you need to maintain a persistent state between scraping sessions? ")
                if self.results["authentication"]["login_required"]:
                    f.write("Yes, likely needed for maintaining authentication sessions")
                else:
                    f.write("Not necessarily based on detected features")
                f.write("\n")
                
                f.write("24. Is there a need for proxy rotation or IP masking? ")
                if self.results["technical_requirements"]["cloudflare_bypass_needed"] or self.results["legal_restrictions"]["rate_limits"]["has_rate_limits"]:
                    f.write("Yes, recommended due to detected protections or rate limits")
                else:
                    f.write("Not necessarily based on detected features")
                f.write("\n")
                
                # Tool Selection Considerations
                f.write("\n## Tool Selection Considerations\n")
                f.write("25. Do you need to render JavaScript? ")
                f.write("Yes" if self.results["website_structure"]["is_dynamic"] else "No")
                f.write("\n")
                
                f.write("26. Do you need to interact with the page (clicking, scrolling, form filling)? ")
                if self.results["data_accessibility"]["js_links_found"] or self.results["authentication"]["login_required"] or self.results["data_accessibility"]["pagination"]["pagination_type"] == "load_more":
                    f.write("Yes, interaction likely needed based on detected features")
                else:
                    f.write("Not necessarily based on detected features")
                f.write("\n")
                
                f.write("27. Are screenshots or PDF captures required? ")
                f.write("Depends on your specific needs\n")
                
                f.write("28. Is browser fingerprint spoofing necessary? ")
                if any(fingerprinting_indicators) or self.results["technical_requirements"]["cloudflare_bypass_needed"]:
                    f.write("Yes, recommended due to detected fingerprinting or protections")
                else:
                    f.write("Not necessarily based on detected features")
                f.write("\n")
                
                # Recommendation summary
                f.write("\n## Tool Recommendation Summary\n")
                
                if self.results["website_structure"]["is_dynamic"] or self.results["authentication"]["login_required"] or self.results["technical_requirements"]["captcha_detected"]:
                    if self.results["technical_requirements"]["cloudflare_bypass_needed"] or any(fingerprinting_indicators):
                        f.write("Recommended tool: Playwright - Best for JavaScript-heavy sites with anti-bot protection\n")
                    else:
                        f.write("Recommended tool: Selenium - Good for JavaScript-heavy sites with interaction needs\n")
                else:
                    f.write("Recommended tool: Scrapy - Most efficient for static content without heavy JavaScript\n")
                    
                f.write("\nAdditional considerations:\n")
                if self.results["technical_requirements"]["cloudflare_bypass_needed"]:
                    f.write("- Use cloudscraper or similar library to bypass Cloudflare protection\n")
                if self.results["legal_restrictions"]["rate_limits"]["has_rate_limits"]:
                    f.write("- Implement rate limiting and request delays to avoid IP blocks\n")
                if self.results["authentication"]["login_required"]:
                    f.write("- Set up session management to handle authentication\n")
                if self.results["data_accessibility"]["pagination"]["has_pagination"]:
                    pagination_type = self.results["data_accessibility"]["pagination"]["pagination_type"]
                    if pagination_type == "infinite_scroll":
                        f.write("- Implement scrolling logic to load all content\n")
                    elif pagination_type == "load_more":
                        f.write("- Implement button clicking to load all content\n")
                    else:
                        f.write("- Implement pagination handling to visit all pages\n")
                
            logger.info(f"Analysis results saved to: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error saving results: {e}")
            return ""


class WebsiteAnalyzerCLI:
    """Command-line interface for the WebsiteAnalyzer."""
    
    def __init__(self):
        """Initialize the CLI parser."""
        self.parser = argparse.ArgumentParser(
            description="Website Scraping Analyzer - Evaluate websites for scraping approach",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        
        self.parser.add_argument(
            "url",
            help="URL of the website to analyze"
        )
        
        self.parser.add_argument(
            "-o", "--output",
            help="Output file path (default: domain_limitations.txt)"
        )
        
        self.parser.add_argument(
            "--no-selenium",
            action="store_true",
            help="Disable Selenium browser automation"
        )
        
        self.parser.add_argument(
            "--use-playwright",
            action="store_true",
            help="Use Playwright for browser automation (if installed)"
        )
        
        self.parser.add_argument(
            "-t", "--timeout",
            type=int,
            default=30,
            help="Request timeout in seconds"
        )
        
        self.parser.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="Enable verbose logging"
        )
    
    def parse_args(self):
        """Parse command-line arguments."""
        return self.parser.parse_args()
    
    def run(self):
        """Run the CLI application."""
        args = self.parse_args()
        
        analyzer = WebsiteAnalyzer(
            url=args.url,
            use_selenium=not args.no_selenium,
            use_playwright=args.use_playwright,
            timeout=args.timeout,
            verbose=args.verbose
        )
        
        try:
            # Run analysis
            print(f"Analyzing website: {args.url}")
            print("This may take a moment...")
            
            results = analyzer.run_analysis()
            
            if "error" in results:
                print(f"Error during analysis: {results['error']}")
                return 1
                
            # Save results
            output_file = analyzer.save_results(args.output)
            
            if output_file:
                print(f"Analysis completed successfully!")
                print(f"Results saved to: {output_file}")
                return 0
            else:
                print("Error saving results.")
                return 1
                
        except KeyboardInterrupt:
            print("\nAnalysis interrupted by user.")
            return 130
        except Exception as e:
            print(f"Unexpected error: {e}")
            return 1


def interactive_mode():
    """Run the analyzer in interactive mode."""
    print("=" * 80)
    print("Website Scraping Analyzer - Interactive Mode")
    print("=" * 80)
    print("This tool will analyze a website and determine the best approach for scraping it.")
    print("It will check for JavaScript dependencies, anti-bot protections, and more.")
    print()
    
    url = input("Enter the website URL to analyze: ").strip()
    
    use_selenium = input("Use Selenium for JavaScript rendering? (y/n) [y]: ").strip().lower()
    use_selenium = use_selenium != 'n'
    
    use_playwright = False
    if PLAYWRIGHT_AVAILABLE:
        use_playwright = input("Use Playwright for additional analysis? (y/n) [n]: ").strip().lower()
        use_playwright = use_playwright == 'y'
    
    timeout = input("Request timeout in seconds [30]: ").strip()
    timeout = int(timeout) if timeout.isdigit() else 30
    
    verbose = input("Enable verbose logging? (y/n) [n]: ").strip().lower()
    verbose = verbose == 'y'
    
    print("\nStarting analysis... This may take a moment.")
    print("=" * 80)
    
    analyzer = WebsiteAnalyzer(
        url=url,
        use_selenium=use_selenium,
        use_playwright=use_playwright,
        timeout=timeout,
        verbose=verbose
    )
    
    try:
        with tqdm(total=100, desc="Analyzing") as pbar:
            # Simulate progress in steps
            pbar.update(10)
            
            # Initial request
            analyzer._make_request()
            pbar.update(20)
            
            # Selenium processing if enabled
            if use_selenium:
                analyzer._fetch_with_selenium()
            pbar.update(30)
            
            # Playwright processing if enabled
            if use_playwright:
                analyzer._fetch_with_playwright()
            pbar.update(20)
            
            # Run full analysis
            results = analyzer.run_analysis()
            pbar.update(20)
            
        if "error" in results:
            print(f"Error during analysis: {results['error']}")
            return
            
        # Save results
        output_file = analyzer.save_results()
        
        if output_file:
            print(f"\nAnalysis completed successfully!")
            print(f"Results saved to: {output_file}")
            
            with open(output_file, 'r', encoding='utf-8') as f:
                print("\nSummary of findings:")
                print("-" * 40)
                for line in f.read().split('\n')[:15]:  # Show first 15 lines
                    print(line)
                print("...")
                print(f"See {output_file} for complete results.")
        else:
            print("Error saving results.")
            
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")


def main():
    """Main entry point."""
    # Check if running as script or interactively
    if len(sys.argv) > 1:
        # CLI mode
        cli = WebsiteAnalyzerCLI()
        sys.exit(cli.run())
    else:
        # Interactive mode
        interactive_mode()


if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required.")
        sys.exit(1)
        
    try:
        import bs4
        import requests
        import tqdm
    except ImportError:
        print("Error: Required dependencies not found.")
        print("Please install required packages:")
        print("pip install beautifulsoup4 requests tqdm cloudscraper selenium webdriver-manager")
        print("Optional: pip install playwright python-whois wappalyzer-python")
        print("To install Playwright browsers: playwright install")
        sys.exit(1)
        
    # Start the application
    main()