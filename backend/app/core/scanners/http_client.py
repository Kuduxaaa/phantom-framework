import httpx

from typing import Dict, Any, Optional


class HTTPClient:
    """
    HTTP client for signature execution.
    """
    def __init__(
        self,
        timeout: int = 30,
        follow_redirects: bool = False,
        proxy: str | None = None,
        headers: dict | None = None,
    ):
        self.timeout = timeout
        self.follow_redirects = follow_redirects

        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=False,
            proxy=proxy,
            headers=headers or {},
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
            ),
        )

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute HTTP request.
        
        Args:
            method: HTTP method
            url: Target URL
            headers: Request headers
            body: Request body
            
        Returns:
            Response dictionary
        """

        try:
            response = await self.client.request(
                method=method,
                url=url,
                headers=headers,
                content=body
            )
            
            return {
                'url': str(response.url),
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text,
                'raw': response.content.decode('utf-8', errors='ignore'),
                'elapsed': response.elapsed.total_seconds(),
            }
            
        except Exception as e:
            return {
                'url': url,
                'status_code': 0,
                'headers': {},
                'body': '',
                'raw': '',
                'error': str(e),
            }
    
    async def close(self):
        """
        Close HTTP client.
        """
        
        await self.client.aclose()