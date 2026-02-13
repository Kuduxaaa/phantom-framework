import re
import base64
import hashlib
import hmac
import json

from typing import Dict, Any, Optional, List
from urllib.parse import urlencode, quote, unquote


class DSLEngine:
    """
	DSL (Domain Specific Language) execution engine.
    
    This engine handles the parsing and execution of dynamic expressions, variables,
    and built-in functions within the scanning signatures. It supports common
    template patterns (e.g., `{{variable}}`) and provides utilities for encoding,
    hashing, and string manipulation.

    Attributes:
        context (Dict[str, Any]): The execution context containing environment details.
        variables (Dict[str, Any]): User-defined or extracted variables.
    """
		
    
    def __init__(self, context: Dict[str, Any] = None):
        """
		Initializes the DSLEngine.

        Args:
            context (Optional[Dict[str, Any]]): Initial context dictionary. 
                Defaults to None.
        """
		
        self.context = context or {}
        self.variables = {}
    
    def set_context(self, key: str, value: Any) -> None:
        """
		Sets a value in the execution context.

        Args:
            key (str): The context key.
            value (Any): The value to store.
        """
		
        self.context[key] = value
    
    def set_variable(self, name: str, value: Any) -> None:
        """
		Sets a user-defined variable.

        Args:
            name (str): The variable name.
            value (Any): The variable value.
        """
		
        self.variables[name] = value
    
    def evaluate(self, expression: str) -> Any:
        """
		Evaluates a DSL expression string.

        Processes variables, context placeholders, and function calls within the string.

        Args:
            expression (str): The DSL string to evaluate.

        Returns:
            Any: The evaluated result (usually a string, but can be other types depending on usage).
        """
		
        result = expression
        
        result = self._replace_variables(result)
        result = self._replace_context(result)
        result = self._evaluate_functions(result)
        
        return result
    
    def _replace_variables(self, text: str) -> str:
        """
		Replaces {{variable_name}} placeholders with their values.

        Args:
            text (str): The input text.

        Returns:
            str: The text with variables substituted.
        """
		
        for var_name, var_value in self.variables.items():
            text = text.replace(f'{{{{{var_name}}}}}', str(var_value))
        
        return text
    
    def _replace_context(self, text: str) -> str:
        """
		Replaces standard context placeholders (e.g., {{BaseURL}}) with values.

        Args:
            text (str): The input text.

        Returns:
            str: The text with context values substituted.
        """
		
        context_map = {
            'BaseURL': self.context.get('base_url', ''),
            'Hostname': self.context.get('hostname', ''),
            'Host': self.context.get('host', ''),
            'Port': str(self.context.get('port', '')),
            'Path': self.context.get('path', ''),
            'File': self.context.get('file', ''),
            'Scheme': self.context.get('scheme', 'https'),
            'RootURL': self.context.get('root_url', ''),
        }
        
        for key, value in context_map.items():
            text = text.replace(f'{{{{{key}}}}}', str(value))
        
        return text
    
    def _evaluate_functions(self, text: str) -> str:
        """
		Finds and executes DSL function calls like {{func(arg1, arg2)}}.

        Args:
            text (str): The input text containing function calls.

        Returns:
            str: The text with function results substituted.
        """
		
        pattern = r'\{\{([a-zA-Z_][a-zA-Z0-9_]*)\((.*?)\)\}\}'
        
        def replace_func(match):
            func_name = match.group(1)
            args_str = match.group(2)
            
            args = self._parse_args(args_str)
            
            if hasattr(self, f'_func_{func_name}'):
                func = getattr(self, f'_func_{func_name}')
                try:
                    return str(func(*args))
                except:
                    return match.group(0)
            
            return match.group(0)
        
        return re.sub(pattern, replace_func, text)
    
    def _parse_args(self, args_str: str) -> List[str]:
        """
		Parses a comma-separated argument string into a list.

        Handles quoted strings to prevent splitting on commas inside quotes.

        Args:
            args_str (str): The raw argument string (e.g., "'a,b', c").

        Returns:
            List[str]: A list of parsed arguments.
        """
		
        if not args_str.strip():
            return []
        
        args = []
        current = []
        in_quotes = False
        quote_char = None
        
        for char in args_str:
            if char in ['"', "'"] and not in_quotes:
                in_quotes = True
                quote_char = char
            elif char == quote_char and in_quotes:
                in_quotes = False
                quote_char = None
            elif char == ',' and not in_quotes:
                args.append(''.join(current).strip().strip('"\''))
                current = []
                continue
            
            current.append(char)
        
        if current:
            args.append(''.join(current).strip().strip('"\''))
        
        return args
    
    def _func_base64(self, text: str) -> str:
        """
		Encodes text to Base64."""
		
        return base64.b64encode(text.encode()).decode()
    
    def _func_base64_decode(self, text: str) -> str:
        """
		Decodes Base64 text."""
		
        return base64.b64decode(text.encode()).decode()
    
    def _func_url_encode(self, text: str) -> str:
        """
		URL-encodes text."""
		
        return quote(text)
    
    def _func_url_decode(self, text: str) -> str:
        """
		Decodes URL-encoded text."""
		
        return unquote(text)
    
    def _func_md5(self, text: str) -> str:
        """
		Calculates MD5 hash of text."""
		
        return hashlib.md5(text.encode()).hexdigest()
    
    def _func_sha1(self, text: str) -> str:
        """
		Calculates SHA1 hash of text."""
		
        return hashlib.sha1(text.encode()).hexdigest()
    
    def _func_sha256(self, text: str) -> str:
        """
		Calculates SHA256 hash of text."""
		
        return hashlib.sha256(text.encode()).hexdigest()
    
    def _func_hex_encode(self, text: str) -> str:
        """
		Encodes text to hexadecimal string."""
		
        return text.encode().hex()
    
    def _func_hex_decode(self, text: str) -> str:
        """
		Decodes hexadecimal string to text."""
		
        return bytes.fromhex(text).decode()
    
    def _func_hmac(self, text: str, key: str, algo: str = 'sha256') -> str:
        """
		Calculates HMAC using specified algorithm (default sha256)."""
		
        algo_func = getattr(hashlib, algo, hashlib.sha256)
        return hmac.new(key.encode(), text.encode(), algo_func).hexdigest()
    
    def _func_len(self, text: str) -> int:
        """
		Returns length of text."""
		
        return len(text)
    
    def _func_to_lower(self, text: str) -> str:
        """
		Converts text to lowercase."""
		
        return text.lower()
    
    def _func_to_upper(self, text: str) -> str:
        """
		Converts text to uppercase."""
		
        return text.upper()
    
    def _func_replace(self, text: str, old: str, new: str) -> str:
        """
		Replaces substrings in text."""
		
        return text.replace(old, new)
    
    def _func_trim(self, text: str) -> str:
        """
		Removes leading/trailing whitespace."""
		
        return text.strip()
    
    def _func_repeat(self, text: str, count: str) -> str:
        """
		Repeats text a specified number of times."""
		
        return text * int(count)
    
    def _func_reverse(self, text: str) -> str:
        """
		Reverses the input text."""
		
        return text[::-1]
    
    def _func_substr(self, text: str, start: str, end: str = None) -> str:
        """
		Extracts a substring."""
		
        start_idx = int(start)
        if end:
            return text[start_idx:int(end)]
        return text[start_idx:]
    
    def _func_rand_int(self, min_val: str, max_val: str) -> int:
        """
		Generates a random integer between min and max."""
		
        import random
        return random.randint(int(min_val), int(max_val))
    
    def _func_rand_text_alphanumeric(self, length: str) -> str:
        """
		Generates random alphanumeric text of specified length."""
		
        import random
        import string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=int(length)))
    
    def _func_rand_text_alpha(self, length: str) -> str:
        """
		Generates random alphabetic text of specified length."""
		
        import random
        import string
        return ''.join(random.choices(string.ascii_letters, k=int(length)))
    
    def _func_rand_text_numeric(self, length: str) -> str:
        """
		Generates random numeric text of specified length."""
		
        import random
        import string
        return ''.join(random.choices(string.digits, k=int(length)))
    
    def evaluate_condition(self, condition: str, response_data: Dict[str, Any]) -> bool:
        """
		Evaluates a boolean condition against response data.

        Sets temporary context variables (status_code, body, etc.) derived from the
        response before evaluating the expression.

        Args:
            condition (str): The boolean expression string (e.g., "status_code == 200").
            response_data (Dict[str, Any]): The HTTP response data.

        Returns:
            bool: The result of the boolean evaluation.
        """
		
        self.set_context('status_code', response_data.get('status_code', 0))
        self.set_context('content_length', len(response_data.get('body', '')))
        self.set_context('body', response_data.get('body', ''))
        self.set_context('headers', response_data.get('headers', {}))
        
        condition = self.evaluate(condition)
        
        try:
            return self._evaluate_boolean_expression(condition, response_data)
        except:
            return False
    
    def _evaluate_boolean_expression(self, expr: str, response_data: Dict[str, Any]) -> bool:
        """
		Parses and executes simple boolean comparison logic.

        Supports operators: contains, ==, !=, >=, <=, >, <.

        Args:
            expr (str): The pre-processed expression string.
            response_data (Dict[str, Any]): The response data for lookup.

        Returns:
            bool: True if the expression evaluates to true, False otherwise.
        """
		
        expr = expr.strip()
        
        if 'contains' in expr:
            match = re.match(r'(.+?)\s+contains\s+["\'](.+?)["\']', expr)
            if match:
                var_name = match.group(1).strip()
                search_term = match.group(2)
                
                if var_name == 'body':
                    return search_term in response_data.get('body', '')
                elif var_name == 'status_code':
                    return search_term in str(response_data.get('status_code', ''))
        
        if '==' in expr:
            parts = expr.split('==')
            if len(parts) == 2:
                left = self._get_value(parts[0].strip(), response_data)
                right = parts[1].strip().strip('"\'')
                return str(left) == right
        
        if '!=' in expr:
            parts = expr.split('!=')

            if len(parts) == 2:
                left = self._get_value(parts[0].strip(), response_data)
                right = parts[1].strip().strip('"\'')
                return str(left) != right
        
        if '>=' in expr:
            parts = expr.split('>=')
            if len(parts) == 2:
                left = self._get_value(parts[0].strip(), response_data)
                right = parts[1].strip()
                return float(left) >= float(right)
        
        if '<=' in expr:
            parts = expr.split('<=')
            if len(parts) == 2:
                left = self._get_value(parts[0].strip(), response_data)
                right = parts[1].strip()
                return float(left) <= float(right)
        
        if '>' in expr:
            parts = expr.split('>')
            if len(parts) == 2:
                left = self._get_value(parts[0].strip(), response_data)
                right = parts[1].strip()
                return float(left) > float(right)
        
        if '<' in expr:
            parts = expr.split('<')
            if len(parts) == 2:
                left = self._get_value(parts[0].strip(), response_data)
                right = parts[1].strip()
                return float(left) < float(right)
        
        return False
    
    def _get_value(self, var_name: str, response_data: Dict[str, Any]) -> Any:
        """
		Retrieves a value for a variable name used in a boolean expression.

        Checks special reserved names (status_code, body) first, then context variables,
        and finally returns the raw string if no variable is found.

        Args:
            var_name (str): The name of the variable to resolve.
            response_data (Dict[str, Any]): The response data.

        Returns:
            Any: The resolved value or the original string.
        """
		
        if var_name == 'status_code':
            return response_data.get('status_code', 0)

        elif var_name == 'content_length':
            return len(response_data.get('body', ''))

        elif var_name.startswith('body'):
            return response_data.get('body', '')
            
        elif var_name in self.variables:
            return self.variables[var_name]
        
        return var_name