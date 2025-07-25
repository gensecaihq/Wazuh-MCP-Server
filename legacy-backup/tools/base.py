"""Base class for Wazuh MCP Server tools."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import mcp.types as types

from ..utils.error_standardization import api_error_handler, StandardErrorResponse
from ..utils.logging import get_logger


class BaseTool(ABC):
    """Abstract base class for all Wazuh MCP Server tools."""
    
    def __init__(self, server_instance):
        """Initialize the tool with a reference to the server instance.
        
        Args:
            server_instance: The main WazuhMCPServer instance
        """
        self.server = server_instance
        self.config = server_instance.config
        self.logger = get_logger(f"{self.__class__.__module__}.{self.__class__.__name__}")
        self.api_client = server_instance.api_client
        self.security_analyzer = server_instance.security_analyzer
        self.compliance_analyzer = server_instance.compliance_analyzer
    
    @property
    @abstractmethod
    def tool_definitions(self) -> List[types.Tool]:
        """Return the MCP tool definitions for this tool category.
        
        Returns:
            List of MCP Tool objects defining the available tools
        """
        pass
    
    @abstractmethod
    def get_handler_mapping(self) -> Dict[str, callable]:
        """Return a mapping of tool names to their handler methods.
        
        Returns:
            Dictionary mapping tool names to handler methods
        """
        pass
    
    @api_error_handler(context={"tool_category": "base"})
    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle a tool call by dispatching to the appropriate handler.
        
        Args:
            name: Tool name
            arguments: Tool arguments
            
        Returns:
            Tool execution result
        """
        handler_mapping = self.get_handler_mapping()
        
        if name not in handler_mapping:
            raise ValueError(f"Unknown tool: {name}")
        
        handler = handler_mapping[name]
        return await handler(arguments)
    
    def _format_response(self, data: Any, success: bool = True, 
                        metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Format a standardized response.
        
        Args:
            data: Response data
            success: Whether the operation was successful
            metadata: Additional metadata
            
        Returns:
            Formatted response dictionary
        """
        response = {
            "success": success,
            "data": data,
            "timestamp": self.server._get_current_timestamp()
        }
        
        if metadata:
            response["metadata"] = metadata
            
        return response
    
    def _format_error_response(self, error: Exception, 
                              context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Format a standardized error response.
        
        Args:
            error: The exception that occurred
            context: Additional error context
            
        Returns:
            Formatted error response
        """
        error_response = StandardErrorResponse(error, context)
        return error_response.to_dict()
    
    def _validate_required_fields(self, arguments: Dict[str, Any], 
                                 required_fields: List[str]) -> None:
        """Validate that required fields are present in arguments.
        
        Args:
            arguments: Tool arguments
            required_fields: List of required field names
            
        Raises:
            ValueError: If any required field is missing
        """
        missing_fields = [field for field in required_fields if field not in arguments]
        if missing_fields:
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
    
    def _get_optional_field(self, arguments: Dict[str, Any], field: str, 
                           default: Any = None) -> Any:
        """Get an optional field from arguments with a default value.
        
        Args:
            arguments: Tool arguments
            field: Field name
            default: Default value if field is not present
            
        Returns:
            Field value or default
        """
        return arguments.get(field, default)