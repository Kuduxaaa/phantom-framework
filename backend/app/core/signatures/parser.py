import yaml
import json
import re

from typing import Dict, Any, Optional, List, Union
from datetime import datetime


class SignatureParser:
    """
    Parse YAML signatures into executable JSON format.
    
    Supports advanced features:
    - Variables and templating
    - Dynamic values ({{BaseURL}}, {{Hostname}})
    - Conditional logic
    - Chained requests with data flow
    - DSL functions (regex, base64, etc.)
    """
    
    @staticmethod
    def parse_yaml(yaml_content: str) -> Dict[str, Any]:
        """
        Parse YAML signature template into JSON.
        
        Args:
            yaml_content: YAML template string
            
        Returns:
            Parsed signature as dictionary
            
        Raises:
            ValueError: If YAML is invalid
        """
        try:
            data = yaml.safe_load(yaml_content)
            
            if not isinstance(data, dict):
                raise ValueError('YAML must be a dictionary')
            
            return SignatureParser._normalize(data)
            
        except yaml.YAMLError as e:
            raise ValueError(f'Invalid YAML: {str(e)}')
    
    @staticmethod
    def _normalize(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize parsed YAML into standard JSON structure.
        
        Args:
            data: Parsed YAML dictionary
            
        Returns:
            Normalized signature dictionary
        """
        signature = {
            'id': data.get('id', ''),
            'name': data.get('name', ''),
            'version': data.get('version', '1.0'),
            'author': data.get('author'),
            'description': data.get('description'),
            'severity': data.get('severity', 'info'),
            'type': data.get('type', 'custom'),
            'tags': data.get('tags', []),
            'references': data.get('references', []),
            'metadata': SignatureParser._parse_metadata(data),
            'variables': data.get('variables', {}),
            'requests': SignatureParser._parse_requests(data.get('requests', [])),
            'matchers': SignatureParser._parse_matchers(data.get('matchers', [])),
            'matchers_condition': data.get('matchers-condition', 'or'),
            'extractors': SignatureParser._parse_extractors(data.get('extractors', [])),
            'self_contained': data.get('self-contained', False),
            'stop_at_first_match': data.get('stop-at-first-match', False),
            'max_redirects': data.get('max-redirects', 10),
        }
        
        if isinstance(signature['tags'], str):
            signature['tags'] = [signature['tags']]
        
        if isinstance(signature['references'], str):
            signature['references'] = [signature['references']]
        
        return signature
    
    @staticmethod
    def _parse_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse metadata from signature.
        
        Args:
            data: Raw signature data
            
        Returns:
            Structured metadata dictionary
        """
        metadata = data.get('info', {}) if 'info' in data else {}
        
        return {
            'cve_id': data.get('cve_id') or metadata.get('cve-id'),
            'cwe_id': data.get('cwe_id') or metadata.get('cwe-id'),
            'cvss_score': data.get('cvss_score') or metadata.get('cvss-score'),
            'cvss_metrics': metadata.get('cvss-metrics'),
            'classification': metadata.get('classification', {}),
            'remediation': metadata.get('remediation'),
            'custom': {k: v for k, v in metadata.items() 
                      if k not in ['cve-id', 'cwe-id', 'cvss-score', 'cvss-metrics', 
                                   'classification', 'remediation']}
        }
    
    @staticmethod
    def _parse_requests(requests: List[Dict]) -> List[Dict]:
        """
        Parse request definitions.
        
        Args:
            requests: List of request configurations
            
        Returns:
            Normalized request list
        """
        normalized = []
        
        for idx, req in enumerate(requests):
            if not isinstance(req, dict):
                continue
            
            normalized_req = {
                'id': req.get('id', f'req_{idx}'),
                'method': req.get('method', 'GET').upper(),
                'path': req.get('path', []),
                'raw': req.get('raw'),
                'headers': req.get('headers', {}),
                'body': req.get('body'),
                'redirects': req.get('redirects', req.get('follow-redirects', False)),
                'max_redirects': req.get('max-redirects', 10),
                'matchers': SignatureParser._parse_matchers(req.get('matchers', [])),
                'matchers_condition': req.get('matchers-condition', 'or'),
                'extractors': SignatureParser._parse_extractors(req.get('extractors', [])),
                'cookie_reuse': req.get('cookie-reuse', True),
                'payloads': req.get('payloads', {}),
                'threads': req.get('threads', 10),
                'attack': req.get('attack', 'batteringram'),
                'req_condition': req.get('req-condition', False),
                'stop_at_first_match': req.get('stop-at-first-match', False),
            }
            
            if isinstance(normalized_req['path'], str):
                normalized_req['path'] = [normalized_req['path']]
            
            if normalized_req['raw']:
                normalized_req['raw'] = SignatureParser._parse_raw_request(
                    normalized_req['raw']
                )
            
            normalized.append(normalized_req)
        
        return normalized
    
    @staticmethod
    def _parse_raw_request(raw: Union[str, List[str]]) -> List[str]:
        """
        Parse raw HTTP request strings.
        
        Args:
            raw: Raw request string or list
            
        Returns:
            List of raw requests
        """
        if isinstance(raw, str):
            return [raw]
        return raw
    
    @staticmethod
    def _parse_matchers(matchers: List[Dict]) -> List[Dict]:
        """
        Parse matcher definitions.
        
        Args:
            matchers: List of matcher configurations
            
        Returns:
            Normalized matcher list
        """
        normalized = []
        
        for matcher in matchers:
            if not isinstance(matcher, dict):
                continue
            
            normalized_matcher = {
                'type': matcher.get('type', 'word'),
                'condition': matcher.get('condition', 'or'),
                'part': matcher.get('part', 'body'),
                'negative': matcher.get('negative', False),
                'name': matcher.get('name'),
                'internal': matcher.get('internal', False),
            }
            
            matcher_type = normalized_matcher['type']
            
            if matcher_type == 'word':
                normalized_matcher['words'] = matcher.get('words', [])
                normalized_matcher['case_insensitive'] = matcher.get('case-insensitive', False)
                
            elif matcher_type == 'regex':
                normalized_matcher['regex'] = matcher.get('regex', [])
                
            elif matcher_type == 'status':
                normalized_matcher['status'] = matcher.get('status', [])
                
            elif matcher_type == 'size':
                normalized_matcher['size'] = matcher.get('size', [])
                
            elif matcher_type == 'binary':
                normalized_matcher['binary'] = matcher.get('binary', [])
                
            elif matcher_type == 'dsl':
                normalized_matcher['dsl'] = matcher.get('dsl', [])
            
            if isinstance(normalized_matcher.get('words'), str):
                normalized_matcher['words'] = [normalized_matcher['words']]
            
            if isinstance(normalized_matcher.get('regex'), str):
                normalized_matcher['regex'] = [normalized_matcher['regex']]
            
            if isinstance(normalized_matcher.get('status'), int):
                normalized_matcher['status'] = [normalized_matcher['status']]
            
            if isinstance(normalized_matcher.get('dsl'), str):
                normalized_matcher['dsl'] = [normalized_matcher['dsl']]
            
            normalized.append(normalized_matcher)
        
        return normalized
    
    @staticmethod
    def _parse_extractors(extractors: List[Dict]) -> List[Dict]:
        """
        Parse extractor definitions.
        
        Args:
            extractors: List of extractor configurations
            
        Returns:
            Normalized extractor list
        """
        normalized = []
        
        for extractor in extractors:
            if not isinstance(extractor, dict):
                continue
            
            normalized_extractor = {
                'type': extractor.get('type', 'regex'),
                'name': extractor.get('name'),
                'part': extractor.get('part', 'body'),
                'internal': extractor.get('internal', False),
            }
            
            extractor_type = normalized_extractor['type']
            
            if extractor_type == 'regex':
                normalized_extractor['regex'] = extractor.get('regex', [])
                normalized_extractor['group'] = extractor.get('group', 1)
                
            elif extractor_type == 'kval':
                normalized_extractor['kval'] = extractor.get('kval', [])
                
            elif extractor_type == 'json':
                normalized_extractor['json'] = extractor.get('json', [])
                
            elif extractor_type == 'xpath':
                normalized_extractor['xpath'] = extractor.get('xpath', [])
                
            elif extractor_type == 'dsl':
                normalized_extractor['dsl'] = extractor.get('dsl', [])
            
            if isinstance(normalized_extractor.get('regex'), str):
                normalized_extractor['regex'] = [normalized_extractor['regex']]
            
            if isinstance(normalized_extractor.get('kval'), str):
                normalized_extractor['kval'] = [normalized_extractor['kval']]
            
            if isinstance(normalized_extractor.get('json'), str):
                normalized_extractor['json'] = [normalized_extractor['json']]
            
            if isinstance(normalized_extractor.get('dsl'), str):
                normalized_extractor['dsl'] = [normalized_extractor['dsl']]
            
            normalized.append(normalized_extractor)
        
        return normalized
    
    @staticmethod
    def to_json(signature: Dict[str, Any]) -> str:
        """
        Convert signature dictionary to JSON string.
        
        Args:
            signature: Signature dictionary
            
        Returns:
            JSON string
        """
        return json.dumps(signature, indent=2)
    
    @staticmethod
    def from_json(json_content: str) -> Dict[str, Any]:
        """
        Parse JSON signature.
        
        Args:
            json_content: JSON string
            
        Returns:
            Signature dictionary
            
        Raises:
            ValueError: If JSON is invalid
        """
        
        try:
            return json.loads(json_content)
        
        except json.JSONDecodeError as e:
            raise ValueError(f'Invalid JSON: {str(e)}')