from typing import Dict, Any, List, Tuple


class SignatureValidator:
    """
    Validate signature templates with advanced feature support.
    """
    
    REQUIRED_FIELDS = ['id', 'name']
    VALID_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
    VALID_MATCHER_TYPES = ['word', 'regex', 'status', 'size', 'binary', 'dsl']
    VALID_EXTRACTOR_TYPES = ['regex', 'kval', 'json', 'xpath', 'dsl']
    VALID_PARTS = ['body', 'header', 'all', 'raw', 'request', 'response', 'interactsh_protocol']
    VALID_CONDITIONS = ['and', 'or']
    VALID_ATTACK_TYPES = ['batteringram', 'pitchfork', 'clusterbomb']
    
    @staticmethod
    def validate(signature: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate signature structure.
        
        Args:
            signature: Signature dictionary
            
        Returns:
            Tuple of (is_valid, error_messages)
        """

        errors = []
        
        for field in SignatureValidator.REQUIRED_FIELDS:
            if field not in signature or not signature[field]:
                errors.append(f'Missing required field: {field}')
        
        if signature.get('severity'):
            if signature['severity'] not in SignatureValidator.VALID_SEVERITIES:
                errors.append(f'Invalid severity: {signature["severity"]}')
        
        if signature.get('requests'):
            request_errors = SignatureValidator._validate_requests(signature['requests'])
            errors.extend(request_errors)
        
        if signature.get('matchers'):
            matcher_errors = SignatureValidator._validate_matchers(signature['matchers'])
            errors.extend(matcher_errors)
        
        if signature.get('extractors'):
            extractor_errors = SignatureValidator._validate_extractors(signature['extractors'])
            errors.extend(extractor_errors)
        
        if signature.get('matchers_condition'):
            if signature['matchers_condition'] not in SignatureValidator.VALID_CONDITIONS:
                errors.append(f'Invalid matchers-condition: {signature["matchers_condition"]}')
        
        if signature.get('variables'):
            if not isinstance(signature['variables'], dict):
                errors.append('Variables must be a dictionary')
        
        return (len(errors) == 0, errors)
    
    @staticmethod
    def _validate_requests(requests: List[Dict]) -> List[str]:
        """
        Validate request configurations.
        """

        errors = []
        
        if not isinstance(requests, list):
            errors.append('Requests must be a list')
            return errors
        
        for idx, request in enumerate(requests):
            if not isinstance(request, dict):
                errors.append(f'Request {idx} must be a dictionary')
                continue
            
            if not request.get('path') and not request.get('raw'):
                errors.append(f'Request {idx}: Must specify either "path" or "raw"')
            
            if request.get('method'):
                method = request['method'].upper()
                valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
                if method not in valid_methods:
                    errors.append(f'Request {idx}: Invalid HTTP method "{method}"')
            
            if request.get('attack'):
                if request['attack'] not in SignatureValidator.VALID_ATTACK_TYPES:
                    errors.append(f'Request {idx}: Invalid attack type "{request["attack"]}"')
            
            if request.get('payloads'):
                if not isinstance(request['payloads'], dict):
                    errors.append(f'Request {idx}: Payloads must be a dictionary')
            
            if request.get('matchers'):
                matcher_errors = SignatureValidator._validate_matchers(
                    request['matchers'], 
                    f'Request {idx}'
                )
                errors.extend(matcher_errors)
            
            if request.get('extractors'):
                extractor_errors = SignatureValidator._validate_extractors(
                    request['extractors'],
                    f'Request {idx}'
                )
                errors.extend(extractor_errors)
            
            if request.get('matchers_condition'):
                if request['matchers_condition'] not in SignatureValidator.VALID_CONDITIONS:
                    errors.append(
                        f'Request {idx}: Invalid matchers-condition "{request["matchers_condition"]}"'
                    )
        
        return errors
    
    @staticmethod
    def _validate_matchers(matchers: List[Dict], prefix: str = '') -> List[str]:
        """
        Validate matcher configurations.
        """

        errors = []
        
        if not isinstance(matchers, list):
            errors.append(f'{prefix} Matchers must be a list'.strip())
            return errors
            
        if len(matchers) == 0:
            return errors
        
        for idx, matcher in enumerate(matchers):
            if not isinstance(matcher, dict):
                errors.append(f'{prefix} Matcher {idx} must be a dictionary'.strip())
                continue
            
            matcher_type = matcher.get('type', 'word')
            
            if matcher_type not in SignatureValidator.VALID_MATCHER_TYPES:
                errors.append(f'{prefix} Matcher {idx}: Invalid type "{matcher_type}"'.strip())
            
            if matcher_type == 'word' and not matcher.get('words'):
                errors.append(f'{prefix} Matcher {idx}: Word matcher requires "words" field'.strip())
            
            if matcher_type == 'regex' and not matcher.get('regex'):
                errors.append(f'{prefix} Matcher {idx}: Regex matcher requires "regex" field'.strip())
            
            if matcher_type == 'status' and not matcher.get('status'):
                errors.append(f'{prefix} Matcher {idx}: Status matcher requires "status" field'.strip())
            
            if matcher_type == 'dsl' and not matcher.get('dsl'):
                errors.append(f'{prefix} Matcher {idx}: DSL matcher requires "dsl" field'.strip())
            
            part = matcher.get('part', 'body')
            if part not in SignatureValidator.VALID_PARTS:
                errors.append(f'{prefix} Matcher {idx}: Invalid part "{part}"'.strip())
            
            condition = matcher.get('condition', 'or')
            if condition not in SignatureValidator.VALID_CONDITIONS:
                errors.append(f'{prefix} Matcher {idx}: Invalid condition "{condition}"'.strip())
        
        return errors
    
    @staticmethod
    def _validate_extractors(extractors: List[Dict], prefix: str = '') -> List[str]:
        """
        Validate extractor configurations.
        """

        errors = []
        
        if not isinstance(extractors, list):
            errors.append(f'{prefix} Extractors must be a list'.strip())
            return errors

        if len(extractors) == 0:
            return errors
        
        for idx, extractor in enumerate(extractors):
            if not isinstance(extractor, dict):
                errors.append(f'{prefix} Extractor {idx} must be a dictionary'.strip())
                continue
            
            extractor_type = extractor.get('type', 'regex')
            
            if extractor_type not in SignatureValidator.VALID_EXTRACTOR_TYPES:
                errors.append(f'{prefix} Extractor {idx}: Invalid type "{extractor_type}"'.strip())
            
            if extractor_type == 'regex' and not extractor.get('regex'):
                errors.append(f'{prefix} Extractor {idx}: Regex extractor requires "regex" field'.strip())
            
            if extractor_type == 'json' and not extractor.get('json'):
                errors.append(f'{prefix} Extractor {idx}: JSON extractor requires "json" field'.strip())
            
            if extractor_type == 'xpath' and not extractor.get('xpath'):
                errors.append(f'{prefix} Extractor {idx}: XPath extractor requires "xpath" field'.strip())
            
            if extractor_type == 'dsl' and not extractor.get('dsl'):
                errors.append(f'{prefix} Extractor {idx}: DSL extractor requires "dsl" field'.strip())
            
            part = extractor.get('part', 'body')
            if part not in SignatureValidator.VALID_PARTS:
                errors.append(f'{prefix} Extractor {idx}: Invalid part "{part}"'.strip())
        
        return errors