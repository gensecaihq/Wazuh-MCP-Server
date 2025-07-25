"""Tool factory for organizing and managing Wazuh MCP Server tools."""

from typing import Dict, List, Any
import mcp.types as types

from .alerts import AlertTools
from .statistics import StatisticsTools
from .vulnerabilities import VulnerabilityTools
from .agents import AgentTools
from .cluster import ClusterTools
from ..utils.logging import get_logger


class ToolFactory:
    """Factory for creating and managing tool instances."""
    
    def __init__(self, server_instance):
        """Initialize tool factory with server instance.
        
        Args:
            server_instance: The main WazuhMCPServer instance
        """
        self.server = server_instance
        self.logger = get_logger(__name__)
        self._tools = {}
        self._initialize_tools()
    
    def _initialize_tools(self):
        """Initialize all tool instances."""
        try:
            # Initialize tool categories
            self._tools['alerts'] = AlertTools(self.server)
            self._tools['statistics'] = StatisticsTools(self.server)
            self._tools['vulnerabilities'] = VulnerabilityTools(self.server)
            self._tools['agents'] = AgentTools(self.server)
            self._tools['cluster'] = ClusterTools(self.server)
            
            self.logger.info(f"Initialized {len(self._tools)} tool categories")
            
        except Exception as e:
            self.logger.error(f"Error initializing tools: {str(e)}")
            # Continue with empty tools dict for graceful degradation
            self._tools = {}
    
    def get_all_tool_definitions(self) -> List[types.Tool]:
        """Get all tool definitions from all categories.
        
        Returns:
            List of all available tool definitions
        """
        all_tools = []
        
        for category_name, tool_instance in self._tools.items():
            try:
                category_tools = tool_instance.tool_definitions
                all_tools.extend(category_tools)
                self.logger.debug(f"Added {len(category_tools)} tools from {category_name}")
            except Exception as e:
                self.logger.error(f"Error getting tools from {category_name}: {str(e)}")
        
        return all_tools
    
    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle a tool call by finding the appropriate handler.
        
        Args:
            name: Tool name
            arguments: Tool arguments
            
        Returns:
            Tool execution result
            
        Raises:
            ValueError: If tool is not found
        """
        # Find which category handles this tool
        for category_name, tool_instance in self._tools.items():
            try:
                handler_mapping = tool_instance.get_handler_mapping()
                if name in handler_mapping:
                    self.logger.debug(f"Handling tool '{name}' with {category_name} category")
                    return await tool_instance.handle_tool_call(name, arguments)
            except Exception as e:
                self.logger.error(f"Error checking {category_name} for tool {name}: {str(e)}")
                continue
        
        # Tool not found in any category
        raise ValueError(f"Unknown tool: {name}")
    
    def get_tool_categories(self) -> List[str]:
        """Get list of available tool categories.
        
        Returns:
            List of category names
        """
        return list(self._tools.keys())
    
    def get_tools_by_category(self, category: str) -> List[types.Tool]:
        """Get tools from a specific category.
        
        Args:
            category: Category name
            
        Returns:
            List of tools in the category
            
        Raises:
            ValueError: If category is not found
        """
        if category not in self._tools:
            raise ValueError(f"Unknown tool category: {category}")
        
        return self._tools[category].tool_definitions
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if tool is available, False otherwise
        """
        for tool_instance in self._tools.values():
            try:
                handler_mapping = tool_instance.get_handler_mapping()
                if tool_name in handler_mapping:
                    return True
            except Exception:
                continue
        
        return False
    
    def get_tool_statistics(self) -> Dict[str, Any]:
        """Get statistics about available tools.
        
        Returns:
            Dictionary with tool statistics
        """
        stats = {
            "total_categories": len(self._tools),
            "total_tools": 0,
            "categories": {}
        }
        
        for category_name, tool_instance in self._tools.items():
            try:
                category_tools = tool_instance.tool_definitions
                tool_count = len(category_tools)
                stats["total_tools"] += tool_count
                stats["categories"][category_name] = {
                    "tool_count": tool_count,
                    "tools": [tool.name for tool in category_tools]
                }
            except Exception as e:
                self.logger.error(f"Error getting stats for {category_name}: {str(e)}")
                stats["categories"][category_name] = {
                    "tool_count": 0,
                    "tools": [],
                    "error": str(e)
                }
        
        return stats