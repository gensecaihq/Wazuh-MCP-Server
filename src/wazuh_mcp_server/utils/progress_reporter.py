"""
FastMCP progress reporting system for long-running security operations.
Implements comprehensive progress tracking and user notifications.
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional, Callable, AsyncGenerator
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
import asyncio
import uuid
import time
from contextlib import asynccontextmanager

from fastmcp import Context
from ..models.fastmcp_models import ProgressUpdate
from ..utils.fastmcp_exceptions import FastMCPError, ErrorCategory


class OperationType(str, Enum):
    """Types of long-running operations."""
    THREAT_ANALYSIS = "threat_analysis"
    ALERT_PROCESSING = "alert_processing"
    AGENT_HEALTH_CHECK = "agent_health_check"
    COMPLIANCE_ASSESSMENT = "compliance_assessment"
    VULNERABILITY_SCAN = "vulnerability_scan"
    INCIDENT_INVESTIGATION = "incident_investigation"
    THREAT_HUNTING = "threat_hunting"
    LOG_ANALYSIS = "log_analysis"
    BULK_EXPORT = "bulk_export"
    SYSTEM_BACKUP = "system_backup"


class OperationStatus(str, Enum):
    """Operation execution status."""
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class OperationStep:
    """Individual step within an operation."""
    step_id: str
    name: str
    description: str
    estimated_duration: Optional[float] = None
    dependencies: List[str] = field(default_factory=list)
    is_critical: bool = False
    status: OperationStatus = OperationStatus.INITIALIZING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None
    progress_percentage: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OperationProgress:
    """Complete progress information for an operation."""
    operation_id: str
    operation_type: OperationType
    operation_name: str
    status: OperationStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Progress metrics
    total_steps: int = 0
    completed_steps: int = 0
    current_step_id: Optional[str] = None
    overall_progress: float = 0.0
    
    # Timing information
    estimated_total_duration: Optional[float] = None
    estimated_completion_time: Optional[datetime] = None
    elapsed_time: float = 0.0
    
    # Step management
    steps: Dict[str, OperationStep] = field(default_factory=dict)
    step_order: List[str] = field(default_factory=list)
    
    # Status information
    success_count: int = 0
    failure_count: int = 0
    warning_count: int = 0
    
    # Error handling
    last_error: Optional[str] = None
    error_count: int = 0
    
    # Metadata
    context_data: Dict[str, Any] = field(default_factory=dict)
    user_id: Optional[str] = None


class ProgressReporter:
    """
    FastMCP-compliant progress reporting system.
    
    Features:
    - Real-time progress updates via FastMCP context
    - Hierarchical step tracking
    - Performance metrics and timing
    - Error handling and recovery
    - Cancellation support
    - Progress persistence
    """
    
    def __init__(self, context: Context):
        """Initialize progress reporter with FastMCP context."""
        self.context = context
        self.active_operations: Dict[str, OperationProgress] = {}
        self.update_interval = 1.0  # seconds
        self._shutdown_event = asyncio.Event()
    
    def create_operation(
        self,
        operation_type: OperationType,
        operation_name: str,
        estimated_duration: Optional[float] = None,
        user_id: Optional[str] = None,
        context_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new trackable operation.
        
        Args:
            operation_type: Type of operation
            operation_name: Human-readable operation name
            estimated_duration: Estimated total duration in seconds
            user_id: User identifier
            context_data: Additional context information
        
        Returns:
            Operation ID for tracking
        """
        operation_id = str(uuid.uuid4())
        
        progress = OperationProgress(
            operation_id=operation_id,
            operation_type=operation_type,
            operation_name=operation_name,
            status=OperationStatus.INITIALIZING,
            created_at=datetime.utcnow(),
            estimated_total_duration=estimated_duration,
            user_id=user_id,
            context_data=context_data or {}
        )
        
        self.active_operations[operation_id] = progress
        return operation_id
    
    def add_step(
        self,
        operation_id: str,
        step_name: str,
        step_description: str,
        estimated_duration: Optional[float] = None,
        dependencies: Optional[List[str]] = None,
        is_critical: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add a step to an operation.
        
        Args:
            operation_id: Operation to add step to
            step_name: Step name
            step_description: Step description
            estimated_duration: Estimated step duration in seconds
            dependencies: List of step IDs this step depends on
            is_critical: Whether step failure should fail the operation
            metadata: Additional step metadata
        
        Returns:
            Step ID for tracking
        """
        if operation_id not in self.active_operations:
            raise FastMCPError(
                message=f"Operation {operation_id} not found",
                category=ErrorCategory.TOOL_VALIDATION,
                context=self.context
            )
        
        step_id = str(uuid.uuid4())
        step = OperationStep(
            step_id=step_id,
            name=step_name,
            description=step_description,
            estimated_duration=estimated_duration,
            dependencies=dependencies or [],
            is_critical=is_critical,
            metadata=metadata or {}
        )
        
        operation = self.active_operations[operation_id]
        operation.steps[step_id] = step
        operation.step_order.append(step_id)
        operation.total_steps = len(operation.steps)
        
        return step_id
    
    async def start_operation(self, operation_id: str) -> None:
        """Start tracking an operation."""
        if operation_id not in self.active_operations:
            raise FastMCPError(
                message=f"Operation {operation_id} not found",
                category=ErrorCategory.TOOL_VALIDATION,
                context=self.context
            )
        
        operation = self.active_operations[operation_id]
        operation.status = OperationStatus.RUNNING
        operation.started_at = datetime.utcnow()
        
        # Calculate estimated completion time
        if operation.estimated_total_duration:
            operation.estimated_completion_time = (
                operation.started_at + timedelta(seconds=operation.estimated_total_duration)
            )
        
        await self.context.info(f"Started operation: {operation.operation_name}")
        await self._report_progress_update(operation)
    
    async def start_step(self, operation_id: str, step_id: str) -> None:
        """Start executing a specific step."""
        operation = self.active_operations.get(operation_id)
        if not operation:
            raise FastMCPError(
                message=f"Operation {operation_id} not found",
                category=ErrorCategory.TOOL_VALIDATION,
                context=self.context
            )
        
        step = operation.steps.get(step_id)
        if not step:
            raise FastMCPError(
                message=f"Step {step_id} not found in operation {operation_id}",
                category=ErrorCategory.TOOL_VALIDATION,
                context=self.context
            )
        
        # Check dependencies
        for dep_id in step.dependencies:
            dep_step = operation.steps.get(dep_id)
            if not dep_step or dep_step.status != OperationStatus.COMPLETED:
                raise FastMCPError(
                    message=f"Step {step_id} dependency {dep_id} not completed",
                    category=ErrorCategory.TOOL_EXECUTION,
                    context=self.context
                )
        
        step.status = OperationStatus.RUNNING
        step.start_time = datetime.utcnow()
        operation.current_step_id = step_id
        
        await self.context.info(f"Starting step: {step.name}")
        await self._report_progress_update(operation)
    
    async def update_step_progress(
        self,
        operation_id: str,
        step_id: str,
        progress_percentage: float,
        status_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Update progress for a specific step."""
        operation = self.active_operations.get(operation_id)
        if not operation:
            return
        
        step = operation.steps.get(step_id)
        if not step:
            return
        
        step.progress_percentage = max(0, min(100, progress_percentage))
        
        if metadata:
            step.metadata.update(metadata)
        
        # Update overall operation progress
        total_progress = sum(s.progress_percentage for s in operation.steps.values())
        operation.overall_progress = total_progress / max(1, len(operation.steps))
        
        # Calculate elapsed time
        if operation.started_at:
            operation.elapsed_time = (datetime.utcnow() - operation.started_at).total_seconds()
        
        # Update estimated completion time based on progress
        if operation.overall_progress > 0 and operation.elapsed_time > 0:
            estimated_total = operation.elapsed_time / (operation.overall_progress / 100)
            operation.estimated_completion_time = (
                operation.started_at + timedelta(seconds=estimated_total)
            )
        
        if status_message:
            await self.context.info(status_message)
        
        await self._report_progress_update(operation)
    
    async def complete_step(
        self,
        operation_id: str,
        step_id: str,
        success: bool = True,
        error_message: Optional[str] = None,
        result_metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Mark a step as completed."""
        operation = self.active_operations.get(operation_id)
        if not operation:
            return
        
        step = operation.steps.get(step_id)
        if not step:
            return
        
        step.end_time = datetime.utcnow()
        step.progress_percentage = 100.0
        
        if success:
            step.status = OperationStatus.COMPLETED
            operation.completed_steps += 1
            operation.success_count += 1
            await self.context.info(f"Completed step: {step.name}")
        else:
            step.status = OperationStatus.FAILED
            step.error_message = error_message
            operation.failure_count += 1
            operation.error_count += 1
            operation.last_error = error_message
            
            await self.context.error(f"Step failed: {step.name} - {error_message}")
            
            # If critical step fails, fail the entire operation
            if step.is_critical:
                await self.fail_operation(operation_id, f"Critical step failed: {step.name}")
                return
        
        if result_metadata:
            step.metadata.update(result_metadata)
        
        # Check if operation is complete
        if operation.completed_steps == operation.total_steps:
            await self.complete_operation(operation_id)
        else:
            await self._report_progress_update(operation)
    
    async def complete_operation(self, operation_id: str) -> None:
        """Mark an operation as completed."""
        operation = self.active_operations.get(operation_id)
        if not operation:
            return
        
        operation.status = OperationStatus.COMPLETED
        operation.completed_at = datetime.utcnow()
        operation.overall_progress = 100.0
        
        if operation.started_at:
            operation.elapsed_time = (operation.completed_at - operation.started_at).total_seconds()
        
        await self.context.info(f"Operation completed: {operation.operation_name}")
        await self._report_progress_update(operation)
        
        # Remove from active operations after a delay
        asyncio.create_task(self._cleanup_operation(operation_id, delay=300))  # 5 minutes
    
    async def fail_operation(
        self,
        operation_id: str,
        error_message: str
    ) -> None:
        """Mark an operation as failed."""
        operation = self.active_operations.get(operation_id)
        if not operation:
            return
        
        operation.status = OperationStatus.FAILED
        operation.completed_at = datetime.utcnow()
        operation.last_error = error_message
        operation.error_count += 1
        
        if operation.started_at:
            operation.elapsed_time = (operation.completed_at - operation.started_at).total_seconds()
        
        await self.context.error(f"Operation failed: {operation.operation_name} - {error_message}")
        await self._report_progress_update(operation)
        
        # Remove from active operations after a delay
        asyncio.create_task(self._cleanup_operation(operation_id, delay=300))  # 5 minutes
    
    async def cancel_operation(self, operation_id: str) -> None:
        """Cancel a running operation."""
        operation = self.active_operations.get(operation_id)
        if not operation:
            return
        
        operation.status = OperationStatus.CANCELLED
        operation.completed_at = datetime.utcnow()
        
        if operation.started_at:
            operation.elapsed_time = (operation.completed_at - operation.started_at).total_seconds()
        
        await self.context.warning(f"Operation cancelled: {operation.operation_name}")
        await self._report_progress_update(operation)
        
        # Remove from active operations immediately for cancelled operations
        asyncio.create_task(self._cleanup_operation(operation_id, delay=60))  # 1 minute
    
    async def _report_progress_update(self, operation: OperationProgress) -> None:
        """Send progress update via FastMCP context."""
        try:
            current_step_name = "Initializing"
            if operation.current_step_id and operation.current_step_id in operation.steps:
                current_step_name = operation.steps[operation.current_step_id].name
            
            progress_update = ProgressUpdate(
                operation_id=operation.operation_id,
                operation_type=operation.operation_type.value,
                current_step=current_step_name,
                progress_percentage=operation.overall_progress,
                completed_items=operation.completed_steps,
                total_items=operation.total_steps,
                status=operation.status.value,
                estimated_completion=operation.estimated_completion_time,
                error_message=operation.last_error
            )
            
            await self.context.report_progress(
                progress=int(operation.overall_progress),
                total=100,
                description=f"{operation.operation_name}: {current_step_name}"
            )
            
        except Exception as e:
            # Don't fail the operation if progress reporting fails
            await self.context.warning(f"Failed to report progress: {str(e)}")
    
    async def _cleanup_operation(self, operation_id: str, delay: int = 0) -> None:
        """Clean up completed/failed operations after delay."""
        if delay > 0:
            await asyncio.sleep(delay)
        
        if operation_id in self.active_operations:
            del self.active_operations[operation_id]
    
    def get_operation_status(self, operation_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of an operation."""
        operation = self.active_operations.get(operation_id)
        if not operation:
            return None
        
        return {
            "operation_id": operation.operation_id,
            "operation_name": operation.operation_name,
            "operation_type": operation.operation_type.value,
            "status": operation.status.value,
            "progress_percentage": operation.overall_progress,
            "completed_steps": operation.completed_steps,
            "total_steps": operation.total_steps,
            "elapsed_time": operation.elapsed_time,
            "estimated_completion": operation.estimated_completion_time.isoformat() + 'Z' if operation.estimated_completion_time else None,
            "success_count": operation.success_count,
            "failure_count": operation.failure_count,
            "error_count": operation.error_count,
            "last_error": operation.last_error
        }
    
    def list_active_operations(self) -> List[Dict[str, Any]]:
        """List all active operations."""
        return [
            self.get_operation_status(op_id)
            for op_id in self.active_operations.keys()
        ]


# ============================================================================
# PROGRESS CONTEXT MANAGER
# ============================================================================

@asynccontextmanager
async def track_progress(
    context: Context,
    operation_type: OperationType,
    operation_name: str,
    steps: List[Dict[str, Any]],
    estimated_duration: Optional[float] = None
) -> AsyncGenerator[ProgressReporter, None]:
    """
    Context manager for automatic progress tracking.
    
    Args:
        context: FastMCP context
        operation_type: Type of operation
        operation_name: Operation name
        steps: List of step definitions
        estimated_duration: Estimated total duration
    
    Usage:
        async with track_progress(ctx, OperationType.THREAT_ANALYSIS, "Analyzing threats", steps) as progress:
            op_id = progress.create_operation(...)
            # ... perform work with progress updates
    """
    reporter = ProgressReporter(context)
    
    try:
        yield reporter
    except Exception as e:
        # Fail any active operations
        for op_id in list(reporter.active_operations.keys()):
            await reporter.fail_operation(op_id, f"Operation failed: {str(e)}")
        raise
    finally:
        # Clean up any remaining operations
        for op_id in list(reporter.active_operations.keys()):
            operation = reporter.active_operations[op_id]
            if operation.status == OperationStatus.RUNNING:
                await reporter.cancel_operation(op_id)