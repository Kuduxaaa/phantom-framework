import asyncio
import itertools
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlparse

from app.core.signatures.parser import SignatureParser
from app.core.signatures.validator import SignatureValidator
from app.core.signatures.matchers import MatcherEngine
from app.core.signatures.executor import SignatureExecutor
from app.core.signatures.dsl import DSLEngine
from app.core.scanners.http_client import HTTPClient


class SignatureScanner:
    """
	Advanced signature-based scanner with chain support.

    This class orchestrates the scanning process using declarative signatures.
    It handles parsing, validation, DSL evaluation, request execution (including
    various payload attack modes), and response matching.
    """
		
    
    def __init__(self, http_client: Optional[HTTPClient] = None, concurrency: int = 10):
        """
		Initializes the SignatureScanner and its dependent engines.

        Args:
            http_client: Optional shared HTTP client for connection pooling.
            concurrency: Max concurrent HTTP requests per template scan.
        """

        self.http_client = http_client or HTTPClient()
        self._owns_client = http_client is None
        self._concurrency = concurrency
        self.parser = SignatureParser()
        self.validator = SignatureValidator()
        self.dsl_engine = DSLEngine()
        self.matcher_engine = MatcherEngine(self.dsl_engine)
        self.executor = SignatureExecutor(self.dsl_engine)
        self.cookies = {}
        self.variables = {}
    
    async def scan_with_yaml(self, yaml_signature: str, target_url: str) -> Dict[str, Any]:
        """
		Parses a YAML signature string and executes the scan.

        Args:
            yaml_signature: The signature definition in YAML format.
            target_url: The target URL to scan.

        Returns:
            A dictionary containing the scan results or error details.
        """
		
        try:
            signature = self.parser.parse_yaml(yaml_signature)
        except ValueError as e:
            return {
                'success': False,
                'error': f'Parse error: {str(e)}'
            }
        
        return await self.scan_with_signature(signature, target_url)
    
    async def scan_with_signature(self, signature: Dict[str, Any], target_url: str) -> Dict[str, Any]:
        """
		Executes a parsed signature dictionary against a target URL.

        Performs validation, sets up the execution context, and iterates through
        defined requests.

        Args:
            signature: The parsed signature dictionary.
            target_url: The target URL to scan.

        Returns:
            A dictionary containing the scan success status, metadata, and matched results.
        """
		
        is_valid, errors = self.validator.validate(signature)
        
        if not is_valid:
            return {
                'success': False,
                'error': 'Validation failed',
                'validation_errors': errors
            }
        
        self._setup_context(target_url)
        
        self.variables = signature.get('variables', {})
        for var_name, var_value in self.variables.items():
            self.dsl_engine.set_variable(var_name, var_value)
        
        requests = signature.get('requests', [])
        
        if not requests:
            requests = [{'method': 'GET', 'path': ['/']}]
        
        all_results = []
        stop_at_first = signature.get('stop_at_first_match', False)
        
        for idx, request_config in enumerate(requests):
            if request_config.get('req_condition'):
                if not self._check_req_condition(request_config, idx):
                    continue
            
            results = await self._execute_request(
                request_config, 
                target_url, 
                signature
            )
            
            all_results.extend(results)
            
            if stop_at_first and results:
                break
            
            if request_config.get('stop_at_first_match') and results:
                break
        
        return {
            'success': True,
            'signature_id': signature.get('id'),
            'signature_name': signature.get('name'),
            'severity': signature.get('severity', 'info'),
            'matched': len(all_results) > 0,
            'results': all_results,
        }
    
    async def _execute_request(
        self, 
        request_config: Dict[str, Any],
        target_url: str,
        signature: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
		Executes a single request configuration.

        Handles standard requests, raw requests, and payload-based attacks.
        Evaluates DSL expressions in headers, bodies, and paths.

        Args:
            request_config: Configuration for the specific request.
            target_url: The base target URL.
            signature: The full signature definition for context.

        Returns:
            A list of result dictionaries for successful matches.
        """
		
        results = []
        
        paths = request_config.get('path', ['/'])
        raw_requests = request_config.get('raw', [])
        method = request_config.get('method', 'GET')
        headers = request_config.get('headers', {})
        body = request_config.get('body')
        
        headers = {k: self.dsl_engine.evaluate(str(v)) for k, v in headers.items()}
        
        if body:
            body = self.dsl_engine.evaluate(body)
        
        payloads = request_config.get('payloads', {})
        
        if payloads:
            results.extend(
                await self._execute_with_payloads(
                    request_config, 
                    target_url, 
                    signature
                )
            )

        elif raw_requests:
            for raw in raw_requests:
                response = await self._execute_raw_request(raw, target_url)
                result = self._process_response(
                    response, 
                    request_config, 
                    signature,
                    target_url
                )
                if result:
                    results.append(result)

        else:
            for path in paths:
                path = self.dsl_engine.evaluate(path)
                url = self._build_url(target_url, path)
                
                response = await self.http_client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    body=body
                )
                
                self._update_context(response)
                
                result = self._process_response(
                    response, 
                    request_config, 
                    signature,
                    url
                )
                
                if result:
                    results.append(result)
                    
                    if request_config.get('stop_at_first_match'):
                        break
        
        return results
    
    async def _execute_with_payloads(
        self,
        request_config: Dict[str, Any],
        target_url: str,
        signature: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
		Dispatches payload-based requests based on the attack type.

        Args:
            request_config: Configuration for the specific request.
            target_url: The base target URL.
            signature: The full signature definition.

        Returns:
            A list of result dictionaries.
        """
		
        results = []
        
        payloads = request_config.get('payloads', {})
        attack_type = request_config.get('attack', 'batteringram')
        
        if attack_type == 'batteringram':
            results.extend(
                await self._attack_batteringram(
                    request_config, 
                    target_url, 
                    signature, 
                    payloads
                )
            )

        elif attack_type == 'pitchfork':
            results.extend(
                await self._attack_pitchfork(
                    request_config, 
                    target_url, 
                    signature, 
                    payloads
                )
            )

        elif attack_type == 'clusterbomb':
            results.extend(
                await self._attack_clusterbomb(
                    request_config, 
                    target_url, 
                    signature, 
                    payloads
                )
            )
        
        return results

    async def _execute_batch(
        self,
        specs: List[Dict[str, Any]],
        request_config: Dict[str, Any],
        signature: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Execute pre-computed request specs concurrently, then match sequentially.

        Args:
            specs: List of dicts with method, url, headers, body, and optional payload/payloads.
            request_config: The request configuration for matching.
            signature: The full signature definition.

        Returns:
            A list of matched result dictionaries.
        """
        if not specs:
            return []

        sem = asyncio.Semaphore(self._concurrency)

        async def _fire(spec):
            async with sem:
                return await self.http_client.request(
                    method=spec['method'],
                    url=spec['url'],
                    headers=spec['headers'],
                    body=spec['body']
                )

        responses = await asyncio.gather(*[_fire(s) for s in specs])

        results = []
        for spec, response in zip(specs, responses):
            self._update_context(response)
            result = self._process_response(
                response, request_config, signature, spec['url']
            )
            if result:
                if 'payload' in spec:
                    result['payload'] = spec['payload']
                if 'payloads' in spec:
                    result['payloads'] = spec['payloads']
                results.append(result)

        return results

    async def _attack_batteringram(
        self,
        request_config: Dict[str, Any],
        target_url: str,
        signature: Dict[str, Any],
        payloads: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """
		Executes a 'batteringram' style attack.

        Uses the same payload from a single list for all placeholders simultaneously.

        Args:
            request_config: Configuration for the request.
            target_url: The base target URL.
            signature: The full signature definition.
            payloads: Dictionary of payload lists.

        Returns:
            A list of result dictionaries.
        """
		
        specs = []
        payload_list = list(payloads.values())[0] if payloads else []

        for payload in payload_list:
            for placeholder in payloads.keys():
                self.dsl_engine.set_variable(placeholder, payload)

            paths = request_config.get('path', ['/'])
            method = request_config.get('method', 'GET')

            for path_tpl in paths:
                path = self.dsl_engine.evaluate(path_tpl)
                url = self._build_url(target_url, path)
                headers = {
                    k: self.dsl_engine.evaluate(str(v))
                    for k, v in request_config.get('headers', {}).items()
                }
                body = request_config.get('body')
                if body:
                    body = self.dsl_engine.evaluate(body)

                specs.append({
                    'method': method,
                    'url': url,
                    'headers': dict(headers),
                    'body': body,
                    'payload': payload,
                })

        return await self._execute_batch(specs, request_config, signature)
    
    async def _attack_pitchfork(
        self,
        request_config: Dict[str, Any],
        target_url: str,
        signature: Dict[str, Any],
        payloads: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """
		Executes a 'pitchfork' style attack.

        Iterates through multiple payload lists in parallel, injecting them into
        corresponding placeholders.

        Args:
            request_config: Configuration for the request.
            target_url: The base target URL.
            signature: The full signature definition.
            payloads: Dictionary of payload lists.

        Returns:
            A list of result dictionaries.
        """
		
        specs = []
        payload_names = list(payloads.keys())
        payload_lists = list(payloads.values())
        min_length = min(len(lst) for lst in payload_lists) if payload_lists else 0

        for i in range(min_length):
            current_payloads = {
                name: payload_lists[idx][i]
                for idx, name in enumerate(payload_names)
            }
            for name, val in current_payloads.items():
                self.dsl_engine.set_variable(name, val)

            paths = request_config.get('path', ['/'])
            method = request_config.get('method', 'GET')

            for path_tpl in paths:
                path = self.dsl_engine.evaluate(path_tpl)
                url = self._build_url(target_url, path)
                headers = {
                    k: self.dsl_engine.evaluate(str(v))
                    for k, v in request_config.get('headers', {}).items()
                }
                body = request_config.get('body')
                if body:
                    body = self.dsl_engine.evaluate(body)

                specs.append({
                    'method': method,
                    'url': url,
                    'headers': dict(headers),
                    'body': body,
                    'payloads': dict(current_payloads),
                })

        return await self._execute_batch(specs, request_config, signature)
    
    async def _attack_clusterbomb(
        self,
        request_config: Dict[str, Any],
        target_url: str,
        signature: Dict[str, Any],
        payloads: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """
		Executes a 'clusterbomb' style attack.

        Iterates through the Cartesian product of all payload lists, testing every
        possible combination.

        Args:
            request_config: Configuration for the request.
            target_url: The base target URL.
            signature: The full signature definition.
            payloads: Dictionary of payload lists.

        Returns:
            A list of result dictionaries.
        """
		
        specs = []
        payload_names = list(payloads.keys())
        payload_lists = list(payloads.values())

        for combination in itertools.product(*payload_lists):
            current_payloads = {
                name: val for name, val in zip(payload_names, combination)
            }
            for name, val in current_payloads.items():
                self.dsl_engine.set_variable(name, val)

            paths = request_config.get('path', ['/'])
            method = request_config.get('method', 'GET')

            for path_tpl in paths:
                path = self.dsl_engine.evaluate(path_tpl)
                url = self._build_url(target_url, path)
                headers = {
                    k: self.dsl_engine.evaluate(str(v))
                    for k, v in request_config.get('headers', {}).items()
                }
                body = request_config.get('body')
                if body:
                    body = self.dsl_engine.evaluate(body)

                specs.append({
                    'method': method,
                    'url': url,
                    'headers': dict(headers),
                    'body': body,
                    'payloads': dict(current_payloads),
                })

        return await self._execute_batch(specs, request_config, signature)
    
    async def _execute_raw_request(self, raw: str, target_url: str) -> Dict[str, Any]:
        """
		Parses and executes a raw HTTP request string.

        Args:
            raw: The raw HTTP request string.
            target_url: The base target URL.

        Returns:
            The HTTP response dictionary.
        """
		
        raw = self.dsl_engine.evaluate(raw)
        
        lines = raw.split('\n')
        if not lines:
            return {}
        
        request_line = lines[0].split()
        if len(request_line) < 2:
            return {}
        
        method = request_line[0]
        path = request_line[1]
        
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                body_start = i + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        body = '\n'.join(lines[body_start:]) if body_start else None
        
        url = self._build_url(target_url, path)
        
        return await self.http_client.request(
            method=method,
            url=url,
            headers=headers,
            body=body
        )
    
    def _process_response(
        self,
        response: Dict[str, Any],
        request_config: Dict[str, Any],
        signature: Dict[str, Any],
        url: str
    ) -> Optional[Dict[str, Any]]:
        """
		Evaluates matchers against the response and extracts data.

        Checks request-specific matchers or falls back to signature-level matchers.
        If matched, executes extractors to capture data or update variables.

        Args:
            response: The HTTP response dictionary.
            request_config: The request configuration used.
            signature: The full signature definition.
            url: The URL that was requested.

        Returns:
            A dictionary containing match details if successful, otherwise None.
        """
		
        request_matchers = request_config.get('matchers', [])
        request_matchers_condition = request_config.get('matchers_condition', 'or')

        if request_matchers:
            matched = self.matcher_engine.match_all(
                request_matchers,
                response,
                request_matchers_condition,
                dsl_engine=self.dsl_engine
            )
        else:
            signature_matchers = signature.get('matchers', [])
            signature_matchers_condition = signature.get('matchers_condition', 'or')

            matched = self.matcher_engine.match_all(
                signature_matchers,
                response,
                signature_matchers_condition,
                dsl_engine=self.dsl_engine
            )
        
        if not matched:
            return None
        
        request_extractors = request_config.get('extractors', [])
        
        if request_extractors:
            extracted = self.executor.extract_all(request_extractors, response)
            
            for extractor in request_extractors:
                if extractor.get('internal') and extractor.get('name'):
                    name = extractor['name']
                    values = self.executor.extract(extractor, response)
                    if values:
                        self.dsl_engine.set_variable(name, values[0])
        else:
            signature_extractors = signature.get('extractors', [])
            extracted = self.executor.extract_all(signature_extractors, response)
        
        return {
            'matched': True,
            'signature_id': signature.get('id'),
            'signature_name': signature.get('name'),
            'severity': signature.get('severity', 'info'),
            'url': url,
            'method': request_config.get('method', 'GET'),
            'status_code': response.get('status_code'),
            'extracted': extracted,
            'metadata': signature.get('metadata', {}),
        }
    
    def _setup_context(self, target_url: str) -> None:
        """
		Sets up the initial DSL context based on the target URL.

        Args:
            target_url: The URL to parse and set in the context.
        """
		
        parsed = urlparse(target_url)
        
        self.dsl_engine.set_context('base_url', target_url)
        self.dsl_engine.set_context('hostname', parsed.hostname or '')
        self.dsl_engine.set_context('host', parsed.netloc or '')
        self.dsl_engine.set_context('port', parsed.port or (443 if parsed.scheme == 'https' else 80))
        self.dsl_engine.set_context('scheme', parsed.scheme or 'https')
        self.dsl_engine.set_context('path', parsed.path or '/')
        self.dsl_engine.set_context('root_url', f'{parsed.scheme}://{parsed.netloc}')
    
    def _update_context(self, response: Dict[str, Any]) -> None:
        """
		Updates the DSL context with response metrics.

        Args:
            response: The HTTP response dictionary.
        """
		
        self.dsl_engine.set_context('status_code', response.get('status_code', 0))
        self.dsl_engine.set_context('content_length', len(response.get('body', '')))
        self.dsl_engine.set_context('duration', response.get('elapsed', 0))
    
    def _check_req_condition(self, request_config: Dict[str, Any], idx: int) -> bool:
        """
		Checks specific preconditions for request execution.

        Args:
            request_config: The configuration for the request.
            idx: The index of the current request in the sequence.

        Returns:
            True if the condition allows execution, False otherwise.
        """
        
        return idx > 0
    
    def _build_url(self, base_url: str, path: str) -> str:
        """
		
        Constructs a full URL from a base and a path.

        Args:
            base_url: The base URL (e.g., https://example.com).
            path: The relative path (e.g., /api/v1).

        Returns:
            The joined full URL.
        """
        
        base_url = base_url.rstrip('/')
        
        if not path.startswith('/'):
            path = '/' + path
        
        return f'{base_url}{path}'
    
    async def close(self):
        """
        Closes the underlying HTTP client resources (only if owned).
        """
        if self._owns_client:
            await self.http_client.close()