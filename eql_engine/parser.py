"""
EQL query parser and tokenizer.

Implements a lightweight tokenizer and recursive descent parser that supports
filter, sequence, and threshold queries with optional timerange and by clauses.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .models import (
    FieldPredicate,
    FilterQuery,
    SequenceQuery,
    ThresholdQuery,
    TimeRange,
)


@dataclass
class Token:
    """Represents a lexical token."""
    type: str
    value: str
    position: int


class Tokenizer:
    """Tokenizes EQL query strings."""
    
    # Token patterns
    TOKEN_PATTERNS = [
        (r'(?i)\bsequence\b', 'SEQUENCE'),
        (r'(?i)\bthreshold\b', 'THRESHOLD'),
        (r'(?i)\bfilter\b', 'FILTER'),
        (r'(?i)\bby\b', 'BY'),
        (r'(?i)\band\b', 'AND'),
        (r'(?i)\bmin_count\b', 'MIN_COUNT'),
        (r'(?i)\btimerange\b', 'TIMERANGE'),
        (r'==', 'EQ'),
        (r'!=', 'NEQ'),
        (r'>=', 'GTE'),
        (r'<=', 'LTE'),
        (r'>', 'GT'),
        (r'<', 'LT'),
        (r'\|', 'PIPE'),
        (r'\[', 'LBRACKET'),
        (r'\]', 'RBRACKET'),
        (r'\(', 'LPAREN'),
        (r'\)', 'RPAREN'),
        (r',', 'COMMA'),
        (r':', 'COLON'),
        (r'=', 'ASSIGN'),
        (r'/[^/]+/', 'REGEX'),
        (r'"[^"]*"', 'STRING'),
        (r"'[^']*'", 'STRING'),
        (r'-?\d+', 'NUMBER'),
        (r'[a-zA-Z_][a-zA-Z0-9_\.]*', 'IDENTIFIER'),
        (r'\s+', 'WHITESPACE'),
    ]
    
    def __init__(self, query: str):
        """Initialize tokenizer with a query string."""
        self.query = query
        self.position = 0
        self.tokens: List[Token] = []
        self._tokenize()
    
    def _tokenize(self) -> None:
        """Tokenize the input query."""
        while self.position < len(self.query):
            matched = False
            
            for pattern, token_type in self.TOKEN_PATTERNS:
                regex = re.compile(pattern)
                match = regex.match(self.query, self.position)
                
                if match:
                    value = match.group(0)
                    
                    if token_type != 'WHITESPACE':
                        self.tokens.append(
                            Token(token_type, value, self.position)
                        )
                    
                    self.position = match.end()
                    matched = True
                    break
            
            if not matched:
                raise SyntaxError(
                    f"Invalid character at position {self.position}: "
                    f"'{self.query[self.position]}'"
                )
    
    def get_tokens(self) -> List[Token]:
        """Return the list of tokens."""
        return self.tokens


class Parser:
    """Parses EQL query tokens into query objects."""
    
    def __init__(self, tokens: List[Token]):
        """Initialize parser with a list of tokens."""
        self.tokens = tokens
        self.position = 0
    
    def _current_token(self) -> Optional[Token]:
        """Get the current token."""
        if self.position < len(self.tokens):
            return self.tokens[self.position]
        return None
    
    def _peek_token(self, offset: int = 1) -> Optional[Token]:
        """Peek at a future token."""
        pos = self.position + offset
        if pos < len(self.tokens):
            return self.tokens[pos]
        return None
    
    def _consume(self, expected_type: Optional[str] = None) -> Token:
        """Consume and return the current token."""
        token = self._current_token()
        if token is None:
            raise SyntaxError("Unexpected end of input")
        if expected_type and token.type != expected_type:
            raise SyntaxError(
                f"Expected {expected_type}, got {token.type}: {token.value}"
            )
        self.position += 1
        return token
    
    def parse(self) -> Tuple[FilterQuery | SequenceQuery | ThresholdQuery, Optional[TimeRange]]:
        """Parse the query and return the query object and optional timerange."""
        query = self._parse_query()
        
        timerange = None
        if self._current_token() and self._current_token().type == 'PIPE':
            self._consume('PIPE')
            timerange = self._parse_timerange()
        
        return query, timerange
    
    def _parse_query(self) -> FilterQuery | SequenceQuery | ThresholdQuery:
        """Parse a query (filter, sequence, or threshold)."""
        current = self._current_token()
        
        if not current:
            raise SyntaxError("Empty query")
        
        if current.type == 'FILTER':
            return self._parse_filter()
        elif current.type == 'SEQUENCE':
            return self._parse_sequence()
        elif current.type == 'THRESHOLD':
            return self._parse_threshold()
        else:
            raise SyntaxError(f"Expected FILTER, SEQUENCE, or THRESHOLD, got {current.type}")
    
    def _parse_filter(self) -> FilterQuery:
        """Parse a filter query."""
        self._consume('FILTER')
        self._consume('LPAREN')
        
        predicates = self._parse_predicates()
        
        self._consume('RPAREN')
        
        by_fields = None
        if self._current_token() and self._current_token().type == 'BY':
            by_fields = self._parse_by_clause()
        
        return FilterQuery(predicates=predicates, by_fields=by_fields)
    
    def _parse_sequence(self) -> SequenceQuery:
        """Parse a sequence query."""
        self._consume('SEQUENCE')
        self._consume('LBRACKET')
        
        filters = []
        while True:
            filters.append(self._parse_filter())
            
            if self._current_token() and self._current_token().type == 'COMMA':
                self._consume('COMMA')
            else:
                break
        
        self._consume('RBRACKET')
        
        by_fields = None
        if self._current_token() and self._current_token().type == 'BY':
            by_fields = self._parse_by_clause()
        
        timerange = None
        if self._current_token() and self._current_token().type == 'PIPE':
            self._consume('PIPE')
            timerange = self._parse_timerange()
        
        return SequenceQuery(filters=filters, timerange=timerange, by_fields=by_fields)
    
    def _parse_threshold(self) -> ThresholdQuery:
        """Parse a threshold query."""
        self._consume('THRESHOLD')
        self._consume('LPAREN')
        
        filter_query = self._parse_filter()
        
        self._consume('COMMA')
        self._consume('MIN_COUNT')
        self._consume('ASSIGN')
        
        min_count_token = self._consume('NUMBER')
        min_count = int(min_count_token.value)
        
        self._consume('RPAREN')
        
        by_fields = None
        if self._current_token() and self._current_token().type == 'BY':
            by_fields = self._parse_by_clause()
        
        timerange = None
        if self._current_token() and self._current_token().type == 'PIPE':
            self._consume('PIPE')
            timerange = self._parse_timerange()
        
        return ThresholdQuery(
            filter=filter_query,
            min_count=min_count,
            timerange=timerange,
            by_fields=by_fields
        )
    
    def _parse_predicates(self) -> List[FieldPredicate]:
        """Parse one or more predicates combined with AND."""
        predicates = [self._parse_predicate()]
        
        while self._current_token() and self._current_token().type == 'AND':
            self._consume('AND')
            predicates.append(self._parse_predicate())
        
        return predicates
    
    def _parse_predicate(self) -> FieldPredicate:
        """Parse a single predicate."""
        # Parse field name
        field_token = self._consume('IDENTIFIER')
        field_name = field_token.value
        
        # Check for colon alias syntax
        if self._current_token() and self._current_token().type == 'COLON':
            self._consume('COLON')
            alias_token = self._consume('IDENTIFIER')
            # Use the alias as field name
            field_name = alias_token.value
        
        # Parse operator
        current = self._current_token()
        if not current or current.type not in ['EQ', 'NEQ', 'GT', 'LT', 'GTE', 'LTE']:
            raise SyntaxError(f"Expected comparison operator, got {current.type if current else 'EOF'}")
        
        operator_token = self._consume()
        operator = operator_token.value
        
        # Parse value
        value_token = self._current_token()
        if not value_token:
            raise SyntaxError("Expected value after operator")
        
        if value_token.type == 'REGEX':
            self._consume('REGEX')
            # Remove the leading and trailing slashes
            regex_pattern = value_token.value[1:-1]
            try:
                compiled_regex = re.compile(regex_pattern)
                return FieldPredicate(
                    field_name=field_name,
                    operator=operator,
                    value=compiled_regex,
                    is_regex=True
                )
            except re.error as e:
                raise SyntaxError(f"Invalid regex pattern: {e}")
        elif value_token.type == 'STRING':
            self._consume('STRING')
            # Remove quotes
            value = value_token.value[1:-1]
            return FieldPredicate(
                field_name=field_name,
                operator=operator,
                value=value,
                is_regex=False
            )
        elif value_token.type == 'NUMBER':
            self._consume('NUMBER')
            value = int(value_token.value)
            return FieldPredicate(
                field_name=field_name,
                operator=operator,
                value=value,
                is_regex=False
            )
        elif value_token.type == 'IDENTIFIER':
            # Allow identifiers as string values (e.g., true, false, null)
            self._consume('IDENTIFIER')
            value = value_token.value
            return FieldPredicate(
                field_name=field_name,
                operator=operator,
                value=value,
                is_regex=False
            )
        else:
            raise SyntaxError(f"Expected value, got {value_token.type}")
    
    def _parse_by_clause(self) -> List[str]:
        """Parse a 'by' clause."""
        self._consume('BY')
        
        fields = [self._consume('IDENTIFIER').value]
        
        while self._current_token() and self._current_token().type == 'COMMA':
            self._consume('COMMA')
            fields.append(self._consume('IDENTIFIER').value)
        
        return fields
    
    def _parse_timerange(self) -> TimeRange:
        """Parse a timerange constraint."""
        self._consume('TIMERANGE')
        
        value_token = self._consume('NUMBER')
        value = int(value_token.value)
        
        unit_token = self._current_token()
        if not unit_token or unit_token.type != 'IDENTIFIER':
            raise SyntaxError("Expected timerange unit (s/m/h)")
        
        unit = unit_token.value.lower()
        if unit not in ['s', 'm', 'h']:
            raise SyntaxError(f"Invalid timerange unit: {unit}")
        
        self._consume('IDENTIFIER')
        
        return TimeRange(value=value, unit=unit)


def parse_query(query: str) -> Tuple[FilterQuery | SequenceQuery | ThresholdQuery, Optional[TimeRange]]:
    """Parse an EQL query string.
    
    Args:
        query: The EQL query string
        
    Returns:
        A tuple of (query_object, optional_timerange)
        
    Raises:
        SyntaxError: If the query is malformed
    """
    tokenizer = Tokenizer(query)
    tokens = tokenizer.get_tokens()
    parser = Parser(tokens)
    return parser.parse()
