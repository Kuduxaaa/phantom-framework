import re
import json

from typing import Dict, Any, List, Optional
from lxml import html as lxml_html


class SignatureExecutor:
    """
	Executes signature extractors with advanced features.

    This class handles the extraction of data from HTTP responses using various
    mechanisms such as Regex, Key-Value matching, JSONPath, XPath, and DSL evaluation.
    """
		
    
    def __init__(self, dsl_engine=None):
        """
		Initializes the SignatureExecutor.

        Args:
            dsl_engine (Optional[DSLEngine]): An instance of the DSL engine used for
                evaluating DSL-based extraction expressions. Defaults to None.
        """
		
        self.dsl_engine = dsl_engine
    
    @staticmethod
    def extract(
        extractor: Dict[str, Any], 
        response: Dict[str, Any],
        dsl_engine=None
    ) -> List[str]:
        """
		Executes a single extraction rule against a response.

        Dispatches the extraction logic based on the 'type' field in the extractor
        configuration. Supported types are 'regex', 'kval', 'json', 'xpath', and 'dsl'.

        Args:
            extractor (Dict[str, Any]): The extraction configuration dictionary.
            response (Dict[str, Any]): The HTTP response data (body, headers, etc.).
            dsl_engine (Optional[DSLEngine]): The DSL engine for evaluation. Defaults to None.

        Returns:
            List[str]: A list of extracted strings. Returns an empty list if no match is found
            or if the content part is missing.
        """
		
        extractor_type = extractor.get('type', 'regex')
        part = extractor.get('part', 'body')
        
        content = SignatureExecutor._get_part(response, part)
        
        if content is None:
            return []
        
        if extractor_type == 'regex':
            return SignatureExecutor._extract_regex(extractor, content)
            
        elif extractor_type == 'kval':
            return SignatureExecutor._extract_kval(extractor, response)
            
        elif extractor_type == 'json':
            return SignatureExecutor._extract_json(extractor, content)
            
        elif extractor_type == 'xpath':
            return SignatureExecutor._extract_xpath(extractor, content)
            
        elif extractor_type == 'dsl':
            return SignatureExecutor._extract_dsl(extractor, response, dsl_engine)
        
        return []
    
    @staticmethod
    def extract_all(
        extractors: List[Dict[str, Any]], 
        response: Dict[str, Any],
        dsl_engine=None
    ) -> Dict[str, List[str]]:
        """
		Executes a list of extractors and aggregates the results.

        Iterates through the provided extractors. Internal extractors are skipped
        in the final output but may be processed if this method is modified to
        handle variable setting (though currently, it just skips 'internal' flagged items).

        Args:
            extractors (List[Dict[str, Any]]): A list of extractor configurations.
            response (Dict[str, Any]): The HTTP response data.
            dsl_engine (Optional[DSLEngine]): The DSL engine for evaluation. Defaults to None.

        Returns:
            Dict[str, List[str]]: A dictionary where keys are the extractor names and
            values are lists of extracted strings.
        """
		
        results = {}
        
        for idx, extractor in enumerate(extractors):
            if extractor.get('internal', False):
                continue
            
            name = extractor.get('name', f'extractor_{idx}')
            
            extracted = SignatureExecutor.extract(extractor, response, dsl_engine)
            
            if extracted:
                results[name] = extracted
        
        return results
    
    @staticmethod
    def _get_part(response: Dict[str, Any], part: str) -> Optional[str]:
        """
		Retrieves the specific part of the response to perform extraction on.

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
    def _extract_regex(extractor: Dict[str, Any], content: str) -> List[str]:
        """
		Performs regex-based extraction.

        Args:
            extractor (Dict[str, Any]): Configuration containing 'regex' patterns and 'group' index.
            content (str): The content string to search against.

        Returns:
            List[str]: A list of matched strings or captured groups.
        """
		
        patterns = extractor.get('regex', [])
        group = extractor.get('group', 1)
        
        results = []
        
        for pattern in patterns:
            try:
                matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
                for match in matches:
                    if group == 0:
                        results.append(match.group(0))
                    elif group <= len(match.groups()):
                        captured = match.group(group)
                        if captured:
                            results.append(captured)
            except re.error:
                continue
        
        return results
    
    @staticmethod
    def _extract_kval(extractor: Dict[str, Any], response: Dict[str, Any]) -> List[str]:
        """
		Performs key-value extraction from response headers.

        Args:
            extractor (Dict[str, Any]): Configuration containing 'kval' keys.
            response (Dict[str, Any]): The response object containing headers.

        Returns:
            List[str]: A list of values corresponding to the specified header keys.
        """
		
        keys = extractor.get('kval', [])
        headers = response.get('headers', {})
        
        results = []
        
        for key in keys:
            key_lower = key.lower()
            for header_key, header_value in headers.items():
                if header_key.lower() == key_lower:
                    results.append(header_value)
                    break
        
        return results
    
    @staticmethod
    def _extract_json(extractor: Dict[str, Any], content: str) -> List[str]:
        """
		Performs extraction from JSON content using dot-notation paths.

        Args:
            extractor (Dict[str, Any]): Configuration containing 'json' paths.
            content (str): The JSON string content.

        Returns:
            List[str]: A list of extracted values converted to strings.
        """
		
        json_paths = extractor.get('json', [])
        
        results = []
        
        try:
            data = json.loads(content)
            
            for path in json_paths:
                value = SignatureExecutor._get_json_path(data, path)
                if value is not None:
                    if isinstance(value, list):
                        results.extend([str(v) for v in value])
                    else:
                        results.append(str(value))
        except json.JSONDecodeError:
            pass
        
        return results
    
    @staticmethod
    def _get_json_path(data: Any, path: str) -> Any:
        """
		Navigates a JSON object using a dot-notation path.

        Args:
            data (Any): The JSON data (dict or list).
            path (str): The path to traverse (e.g., 'users.0.id').

        Returns:
            Any: The value at the specified path, or None if the path does not exist.
        """
		
        parts = path.split('.')
        current = data
        
        for part in parts:
            if isinstance(current, dict):
                if part in current:
                    current = current[part]
                else:
                    return None
            elif isinstance(current, list):
                try:
                    idx = int(part)
                    if 0 <= idx < len(current):
                        current = current[idx]
                    else:
                        return None
                except ValueError:
                    return None
            else:
                return None
        
        return current
    
    @staticmethod
    def _extract_xpath(extractor: Dict[str, Any], content: str) -> List[str]:
        """
		Performs XPath-based extraction on HTML/XML content.

        Args:
            extractor (Dict[str, Any]): Configuration containing 'xpath' queries.
            content (str): The HTML or XML content string.

        Returns:
            List[str]: A list of text content from matched elements.
        """
		
        xpath_queries = extractor.get('xpath', [])
        
        results = []
        
        try:
            tree = lxml_html.fromstring(content)
            
            for xpath in xpath_queries:
                elements = tree.xpath(xpath)
                
                for element in elements:
                    if isinstance(element, str):
                        results.append(element)
                    elif hasattr(element, 'text'):
                        if element.text:
                            results.append(element.text)
                    else:
                        results.append(str(element))
        except:
            pass
        
        return results
    
    @staticmethod
    def _extract_dsl(
        extractor: Dict[str, Any], 
        response: Dict[str, Any],
        dsl_engine
    ) -> List[str]:
        """
		Evaluates DSL expressions to extract data.

        Args:
            extractor (Dict[str, Any]): Configuration containing 'dsl' expressions.
            response (Dict[str, Any]): The response object context.
            dsl_engine (DSLEngine): The engine to evaluate expressions.

        Returns:
            List[str]: A list of results from evaluated DSL expressions.
        """
		
        if not dsl_engine:
            return []
        
        dsl_expressions = extractor.get('dsl', [])
        
        results = []
        
        for expr in dsl_expressions:
            try:
                value = dsl_engine.evaluate(expr)
                if value:
                    results.append(str(value))
            except:
                continue
        
        return results