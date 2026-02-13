import re

from typing import Dict, Any, List, Optional


class MatcherEngine:
    """
	Executes matchers against HTTP responses with DSL support.

    This class provides the core logic for evaluating various types of matchers
    (word, regex, status, size, binary, DSL) against HTTP response data.
    """
		
    
    def __init__(self, dsl_engine=None):
        """
		Initializes the MatcherEngine.

        Args:
            dsl_engine (Optional[DSLEngine]): The DSL engine used for evaluating
                DSL-based match conditions. Defaults to None.
        """
		
        self.dsl_engine = dsl_engine
    
    @staticmethod
    def match(matcher: Dict[str, Any], response: Dict[str, Any], dsl_engine=None) -> bool:
        """
		Evaluates a single matcher configuration against a response.

        Dispatches the matching logic to specific private methods based on the
        matcher type (e.g., 'word', 'regex', 'status'). Handles the 'negative'
        flag to invert results.

        Args:
            matcher (Dict[str, Any]): The matcher configuration dictionary.
            response (Dict[str, Any]): The HTTP response object.
            dsl_engine (Optional[DSLEngine]): The DSL engine for evaluation.

        Returns:
            bool: True if the matcher condition is met, False otherwise.
        """
		
        matcher_type = matcher.get('type', 'word')
        part = matcher.get('part', 'body')
        negative = matcher.get('negative', False)
        
        content = MatcherEngine._get_part(response, part)
        
        if content is None:
            return negative
        
        result = False
        
        if matcher_type == 'word':
            result = MatcherEngine._match_word(matcher, content)
            
        elif matcher_type == 'regex':
            result = MatcherEngine._match_regex(matcher, content)
            
        elif matcher_type == 'status':
            result = MatcherEngine._match_status(matcher, response)
            
        elif matcher_type == 'size':
            result = MatcherEngine._match_size(matcher, content)
            
        elif matcher_type == 'binary':
            result = MatcherEngine._match_binary(matcher, content)
            
        elif matcher_type == 'dsl':
            result = MatcherEngine._match_dsl(matcher, response, dsl_engine)
        
        return not result if negative else result
    
    @staticmethod
    def match_all(
        matchers: List[Dict[str, Any]], 
        response: Dict[str, Any], 
        condition: str = 'or',
        dsl_engine=None
    ) -> bool:
        """
		Evaluates a list of matchers and combines their results.

        Handles the aggregation of multiple matchers using 'and'/'or' logic.
        If 'internal' matchers are present, they are processed but excluded from
        the final boolean result calculation.

        Args:
            matchers (List[Dict[str, Any]]): A list of matcher configurations.
            response (Dict[str, Any]): The HTTP response object.
            condition (str): The logical condition to combine results ('and' or 'or').
                Defaults to 'or'.
            dsl_engine (Optional[DSLEngine]): The DSL engine for evaluation.

        Returns:
            bool: The combined result of the matchers.
        """
		
        if not matchers:
            return False
        
        results = [MatcherEngine.match(m, response, dsl_engine) for m in matchers]
        
        internal_matchers = [m for m in matchers if m.get('internal', False)]
        if internal_matchers:
            results = [
                MatcherEngine.match(m, response, dsl_engine) 
                for m in matchers 
                if not m.get('internal', False)
            ]
        
        if not results:
            return False
        
        if condition == 'and':
            return all(results)
        else:
            return any(results)
    
    @staticmethod
    def _get_part(response: Dict[str, Any], part: str) -> Optional[str]:
        """
		Retrieves specific parts of the response for matching.

        Args:
            response (Dict[str, Any]): The HTTP response object.
            part (str): The name of the part to retrieve ('body', 'header', 'all',
                'raw', 'request', 'response').

        Returns:
            Optional[str]: The content of the requested part, or None if invalid.
        """
		
        if part == 'body':
            return response.get('body', '')
            
        elif part == 'header':
            headers = response.get('headers', {})
            return '\n'.join([f'{k}: {v}' for k, v in headers.items()])
            
        elif part == 'all':
            body = response.get('body', '')
            headers = response.get('headers', {})
            header_str = '\n'.join([f'{k}: {v}' for k, v in headers.items()])
            return f'{header_str}\n\n{body}'
            
        elif part == 'raw':
            return response.get('raw', response.get('body', ''))
            
        elif part == 'request':
            return response.get('request', '')
            
        elif part == 'response':
            return response.get('body', '')
        
        return None
    
    @staticmethod
    def _match_word(matcher: Dict[str, Any], content: str) -> bool:
        """
		Checks if specific words are present in the content.

        Args:
            matcher (Dict[str, Any]): Configuration containing 'words', 'case_insensitive',
                and 'condition'.
            content (str): The text content to search.

        Returns:
            bool: True if the word condition is met.
        """
		
        words = matcher.get('words', [])
        case_insensitive = matcher.get('case_insensitive', False)
        condition = matcher.get('condition', 'or')
        
        if case_insensitive:
            content = content.lower()
            words = [w.lower() for w in words]
        
        results = [word in content for word in words]
        
        if condition == 'and':
            return all(results)
        else:
            return any(results)
    
    @staticmethod
    def _match_regex(matcher: Dict[str, Any], content: str) -> bool:
        """
		Checks if regex patterns match the content.

        Args:
            matcher (Dict[str, Any]): Configuration containing 'regex' patterns and 'condition'.
            content (str): The text content to search.

        Returns:
            bool: True if the regex condition is met.
        """
		
        patterns = matcher.get('regex', [])
        condition = matcher.get('condition', 'or')
        
        results = []
        for pattern in patterns:
            try:
                match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
                results.append(match is not None)
            except re.error:
                results.append(False)
        
        if condition == 'and':
            return all(results)
        else:
            return any(results)
    
    @staticmethod
    def _match_status(matcher: Dict[str, Any], response: Dict[str, Any]) -> bool:
        """
		Checks if the response status code matches expected values.

        Args:
            matcher (Dict[str, Any]): Configuration containing 'status' list.
            response (Dict[str, Any]): The HTTP response object.

        Returns:
            bool: True if the status code matches.
        """
		
        expected_status = matcher.get('status', [])
        actual_status = response.get('status_code', 0)
        
        return actual_status in expected_status
    
    @staticmethod
    def _match_size(matcher: Dict[str, Any], content: str) -> bool:
        """
		Checks if the content size matches expected values.

        Args:
            matcher (Dict[str, Any]): Configuration containing 'size' list.
            content (str): The content to measure.

        Returns:
            bool: True if the content length is in the expected sizes.
        """
		
        expected_sizes = matcher.get('size', [])
        actual_size = len(content)
        
        return actual_size in expected_sizes
    
    @staticmethod
    def _match_binary(matcher: Dict[str, Any], content: str) -> bool:
        """
		Checks for the presence of binary patterns (hex strings) in the content.

        Args:
            matcher (Dict[str, Any]): Configuration containing 'binary' patterns.
            content (str): The content to search (will be encoded to latin-1 if string).

        Returns:
            bool: True if any binary pattern is found.
        """
		
        patterns = matcher.get('binary', [])
        
        content_bytes = content.encode('latin-1') if isinstance(content, str) else content
        
        for pattern in patterns:
            if isinstance(pattern, str):
                pattern_bytes = bytes.fromhex(pattern.replace(' ', ''))
            else:
                pattern_bytes = pattern
            
            if pattern_bytes in content_bytes:
                return True
        
        return False
    
    @staticmethod
    def _match_dsl(matcher: Dict[str, Any], response: Dict[str, Any], dsl_engine) -> bool:
        """
		Evaluates DSL expressions for matching.

        Args:
            matcher (Dict[str, Any]): Configuration containing 'dsl' expressions and 'condition'.
            response (Dict[str, Any]): The HTTP response object.
            dsl_engine (DSLEngine): The engine to evaluate expressions.

        Returns:
            bool: True if the DSL condition is met.
        """
		
        if not dsl_engine:
            return False
        
        dsl_expressions = matcher.get('dsl', [])
        condition = matcher.get('condition', 'or')
        
        results = []
        for expr in dsl_expressions:
            try:
                result = dsl_engine.evaluate_condition(expr, response)
                results.append(result)
            except:
                results.append(False)
        
        if condition == 'and':
            return all(results)
        else:
            return any(results)