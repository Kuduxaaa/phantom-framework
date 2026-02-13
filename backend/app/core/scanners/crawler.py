"""
Phantom Framework - Web Crawler

Discovers pages, URL parameters, and HTML forms on the target
for directed vulnerability scanning.
"""

import asyncio

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from typing import Dict, Any, List, Set, Optional, Callable


IGNORED_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.bmp',
    '.css', '.js', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
}


class LinkExtractor(HTMLParser):
    """
    Extract links and forms from HTML content.

    Parses anchor hrefs, form actions with their inputs,
    and resource URLs (script, img, link, iframe).
    """

    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self._form: Optional[Dict[str, Any]] = None
        self._inputs: List[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = dict(attrs)

        if tag == 'a':
            href = a.get('href')
            if href:
                self.links.append(href)

        elif tag == 'form':
            self._form = {
                'action': a.get('action', ''),
                'method': a.get('method', 'GET').upper(),
            }
            self._inputs = []

        elif tag in ('input', 'textarea', 'select') and self._form is not None:
            name = a.get('name')
            if name:
                self._inputs.append(name)

        elif tag in ('script', 'img', 'link', 'iframe'):
            src = a.get('src') or a.get('href')
            if src:
                self.links.append(src)

    def handle_endtag(self, tag: str) -> None:
        if tag == 'form' and self._form is not None:
            self._form['inputs'] = self._inputs
            self.forms.append(self._form)
            self._form = None
            self._inputs = []


class Crawler:
    """
    Asynchronous web crawler for endpoint discovery.

    Performs breadth-first crawling of the target to discover pages,
    URL parameters, and HTML forms. Returns injection paths that can
    be merged into signature templates for directed scanning.
    """

    def __init__(
        self,
        http_client,
        max_depth: int = 3,
        max_pages: int = 50,
        concurrency: int = 10,
    ):
        """
        Initialize the crawler.

        Args:
            http_client: Shared HTTPClient instance for requests.
            max_depth: Maximum link depth to follow from start URL.
            max_pages: Maximum number of pages to fetch.
            concurrency: Maximum concurrent HTTP requests.
        """
        self.http_client = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency

        self._visited: Set[str] = set()
        self._seen_params: Set[tuple] = set()
        self._injection_paths: List[str] = []
        self._forms: List[Dict[str, Any]] = []
        self._base_netloc = ""

    async def crawl(
        self,
        start_url: str,
        on_page: Optional[Callable] = None,
    ) -> Dict[str, Any]:
        """
        Crawl the target starting from start_url.

        Performs BFS traversal following same-origin links up to max_depth.
        Extracts URL parameters and form inputs as injection points.

        Args:
            start_url: The URL to start crawling from.
            on_page: Optional callback(url_path, link_count) called per page.

        Returns:
            Dictionary with crawl stats and discovered injection paths.
        """
        parsed = urlparse(start_url)
        self._base_netloc = parsed.netloc

        queue = [(start_url, 0)]
        sem = asyncio.Semaphore(self.concurrency)

        while queue and len(self._visited) < self.max_pages:
            batch = []

            while queue and len(batch) < self.concurrency:
                url, depth = queue.pop(0)
                norm = self._normalize(url)
                
                if norm in self._visited or depth > self.max_depth:
                    continue

                self._visited.add(norm)
                batch.append((url, depth))

            if not batch:
                break

            async def _fetch(u: str):
                async with sem:
                    return await self.http_client.request('GET', u)

            responses = await asyncio.gather(
                *[_fetch(url) for url, _ in batch]
            )

            for (url, depth), response in zip(batch, responses):
                status = response.get('status_code', 0)

                # Follow redirects manually
                if status in (301, 302, 303, 307, 308):
                    location = self._get_header(response, 'location')
                    
                    if location:
                        redir = urljoin(url, location)
                        if self._should_follow(redir):
                            norm = self._normalize(redir)
                            if norm not in self._visited:
                                queue.append((redir, depth))
                    continue

                if response.get('error') or status == 0:
                    continue

                content_type = self._get_header(response, 'content-type')
                if content_type and 'html' not in content_type:
                    continue

                body = response.get('body', '')
                extractor = LinkExtractor()
                try:
                    extractor.feed(body)
                except Exception:
                    continue

                # Record URL parameters as injection points
                self._extract_params(url)

                # Enqueue discovered links
                new_links = 0
                for link in extractor.links:
                    full = urljoin(url, link)
                    if self._should_follow(full):
                        norm = self._normalize(full)
                        if norm not in self._visited:
                            queue.append((full, depth + 1))
                            new_links += 1

                # Record form inputs
                for form in extractor.forms:
                    action = urljoin(url, form['action']) if form['action'] else url
                    if self._is_same_origin(action):
                        self._forms.append({
                            'path': urlparse(action).path or '/',
                            'method': form['method'],
                            'inputs': form['inputs'],
                        })

                if on_page:
                    p = urlparse(url)
                    display = p.path + ('?' + p.query if p.query else '')
                    on_page(display, new_links)

        # Build injection paths from forms (GET only)
        self._extract_form_params()

        return {
            'pages_crawled': len(self._visited),
            'parameters': len(self._seen_params),
            'forms_found': len(self._forms),
            'injection_paths': sorted(self._injection_paths),
        }

    def _normalize(self, url: str) -> str:
        """
        Normalize a URL for deduplication (strip fragment).
        """
        
        parsed = urlparse(url)
        path = parsed.path or '/'
        
        return urlunparse((
            parsed.scheme, parsed.netloc, path,
            '', parsed.query, ''
        ))

    def _is_same_origin(self, url: str) -> bool:
        """
        Check if URL belongs to the same origin as the target.
        """
        
        return urlparse(url).netloc == self._base_netloc

    def _should_follow(self, url: str) -> bool:
        """
        Determine if a URL should be followed during crawling.
        """
        
        if not self._is_same_origin(url):
            return False

        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https', ''):
            return False

        path = parsed.path.lower()
        for ext in IGNORED_EXTENSIONS:
            if path.endswith(ext):
                return False

        return True

    @staticmethod
    def _get_header(response: Dict[str, Any], name: str) -> str:
        """
        Get a response header value (case-insensitive).
        """
        
        for k, v in response.get('headers', {}).items():
            if k.lower() == name.lower():
                return v
            
        return ''

    def _extract_params(self, url: str) -> None:
        """
        Extract query parameters from a URL as injection points.
        """
        
        parsed = urlparse(url)
        if not parsed.query:
            return

        params = parse_qs(parsed.query, keep_blank_values=True)

        for target_param in params:
            key = (parsed.path, target_param)
            if key in self._seen_params:
                continue
            self._seen_params.add(key)

            # Build injection path preserving other params
            parts = []
            for name, values in params.items():
                if name == target_param:
                    parts.append(f"{name}={{{{payload}}}}")
                else:
                    parts.append(f"{name}={values[0] if values else ''}")

            self._injection_paths.append(
                f"{parsed.path}?{'&'.join(parts)}"
            )

    def _extract_form_params(self) -> None:
        """
        Extract GET form inputs as injection points.
        """
        
        for form in self._forms:
            if form['method'] != 'GET':
                continue

            for target_input in form['inputs']:
                key = (form['path'], target_input)
                if key in self._seen_params:
                    continue

                self._seen_params.add(key)
                parts = []

                for input_name in form['inputs']:
                    if input_name == target_input:
                        parts.append(f"{input_name}={{{{payload}}}}")
                    else:
                        parts.append(f"{input_name}=")

                self._injection_paths.append(
                    f"{form['path']}?{'&'.join(parts)}"
                )
