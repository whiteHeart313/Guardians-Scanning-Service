import redis
import json
import time
import logging
from typing import Optional, Dict, Any

class RedisPubSub:
    """Redis Pub/Sub singleton class for SpiderFoot notifications."""
    
    _instance: Optional['RedisPubSub'] = None
    _redis_client: Optional[redis.Redis] = None
    
    def __new__(cls) -> 'RedisPubSub':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        # Always try to connect, even if it fails initially
        if self._redis_client is None:
            self._connect()
    
    def _connect(self) -> None:
        """Initialize Redis connection with error handling."""
        try:
            self._redis_client = redis.Redis(
                host='localhost', 
                port=6379, 
                db=0,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30
            )
            # Test the connection
            self._redis_client.ping()
            logging.info("Successfully connected to Redis")
        except redis.ConnectionError as e:
            logging.warning(f"Failed to connect to Redis: {e}")
            self._redis_client = None
        except Exception as e:
            logging.warning(f"Unexpected error connecting to Redis: {e}")
            self._redis_client = None
    
    def reconnect(self) -> bool:
        """Force a reconnection attempt.
        
        Returns:
            bool: True if reconnection successful
        """
        logging.info("Forcing Redis reconnection...")
        self._redis_client = None
        self._connect()
        return self.is_connected()
    
    def is_connected(self) -> bool:
        """Check if Redis connection is active."""
        if self._redis_client is None:
            return False
        try:
            self._redis_client.ping()
            return True
        except:
            return False
    
    def publish(self, channel: str, message: Dict[str, Any]) -> bool:
        """Publish message to Redis channel with error handling."""
        if not self.is_connected():
            logging.warning("Redis not connected, attempting to reconnect...")
            self._connect()
            
        if not self.is_connected():
            logging.error("Failed to publish message: Redis not available")
            return False
        
        try:
            result = self._redis_client.publish(channel, json.dumps(message))
            logging.debug(f"Published message to {channel}, subscribers: {result}")
            return True
        except Exception as e:
            logging.error(f"Failed to publish message to {channel}: {e}")
            return False

# Global instance
_redis_pubsub = RedisPubSub()

def notify_asset_scan_completed(asset_data: Dict[str, Any]) -> bool:
    """Notify that an asset scan has been completed.
    
    Args:
        asset_data: Dictionary containing asset information with 'id' key
        
    Returns:
        bool: True if notification was sent successfully, False otherwise
    """
    if not isinstance(asset_data, dict) or 'id' not in asset_data:
        logging.error("Invalid asset_data: must be dict with 'id' key")
        return False
        
    message = {
        'event': 'asset_scan_completed',
        'asset_id': asset_data['id'],
        'timestamp': time.time(),
        'data': asset_data
    }
    
    return _redis_pubsub.publish('asset_notifications', message)


def notify_scan_failed(scan_id: str, target: str, scan_name: str, status: str = "ERROR-FAILED", error: str = None) -> bool:
    """Notify that a scan has failed.
    
    Args:
        scan_id: Unique scan identifier
        target: Scan target
        scan_name: Human readable scan name
        status: Failure status (ERROR-FAILED, ABORT-REQUESTED, etc.)
        error: Error message if available
        
    Returns:
        bool: True if notification was sent successfully
    """
    message = {
        'event': 'scan_failed',
        'scan_id': scan_id,
        'target': target,
        'scan_name': scan_name,
        'status': status,
        'error': error,
        'timestamp': time.time()
    }
    
    return _redis_pubsub.publish('scan_notifications', message)

def notify_scan_started(scan_id: str, target: str, scan_name: str) -> bool:
    """Notify that a new scan has started.
    
    Args:
        scan_id: Unique scan identifier
        target: Scan target (email, domain, etc.)
        scan_name: Human readable scan name
        
    Returns:
        bool: True if notification was sent successfully
    """
    message = {
        'event': 'scan_started',
        'scan_id': scan_id,
        'target': target,
        'scan_name': scan_name,
        'timestamp': time.time()
    }
    
    return _redis_pubsub.publish('scan_notifications', message)

def notify_scan_completed(scan_id: str, status: str, results_count: int = 0) -> bool:
    """Notify that a scan has completed.
    
    Args:
        scan_id: Unique scan identifier
        status: Scan completion status (FINISHED, ERROR-FAILED, ABORTED)
        results_count: Number of results found
        
    Returns:
        bool: True if notification was sent successfully
    """
    message = {
        'event': 'scan_completed',
        'scan_id': scan_id,
        'status': status,
        'results_count': results_count,
        'timestamp': time.time()
    }
    
    return _redis_pubsub.publish('scan_notifications', message)

def notify_new_finding(scan_id: str, event_type: str, data: str, source: str) -> bool:
    """Notify about a new finding during scan.
    
    Args:
        scan_id: Unique scan identifier
        event_type: Type of event found (EMAILADDR, IP_ADDRESS, etc.)
        data: The actual data found
        source: Source module that found the data
        
    Returns:
        bool: True if notification was sent successfully
    """
    message = {
        'event': 'new_finding',
        'scan_id': scan_id,
        'event_type': event_type,
        'data': data,
        'source': source,
        'timestamp': time.time()
    }
    
    return _redis_pubsub.publish('findings_notifications', message)

def calculate_risk_status(scan_results: Dict[str, int]) -> str:
    """Calculate risk status based on scan results.
    
    Args:
        scan_results: Dictionary with event types and their counts
        
    Returns:
        str: Risk level (CRITICAL, HIGH, MEDIUM, LOW, NONE)
    """
    # Define risk weights for different event types
    risk_weights = {
        'VULNERABILITY_CRITICAL': 100,
        'VULNERABILITY_HIGH': 80,
        'MALICIOUS_IPADDR': 90,
        'MALICIOUS_EMAILADDR': 85,
        'MALICIOUS_INTERNET_NAME': 85,
        'VULNERABILITY_MEDIUM': 60,
        'VULNERABILITY_LOW': 40,
        'DARKWEB_MENTION': 70,
        'BREACH_DATA': 75,
        'DEFACED_IPADDR': 65,
        'DEFACED_INTERNET_NAME': 65,
        'BLACKLISTED_IPADDR': 70,
        'BLACKLISTED_INTERNET_NAME': 70,
        'LEAK_SITE': 60,
        'SOCIAL_MEDIA': 30,
        'EMAILADDR': 20,
        'PHONE_NUMBER': 25,
        'PHYSICAL_ADDRESS': 30,
        'WEBSERVER_TECHNOLOGY': 10,
        'OPERATING_SYSTEM': 15,
        'SOFTWARE_USED': 10
    }
    
    total_risk_score = 0
    total_findings = 0
    
    for event_type, count in scan_results.items():
        if count > 0:
            weight = risk_weights.get(event_type, 5)  # Default low weight
            total_risk_score += weight * count
            total_findings += count
    
    if total_findings == 0:
        return "NONE"
    
    # Calculate average risk per finding
    avg_risk = total_risk_score / total_findings
    
    if avg_risk >= 80:
        return "CRITICAL"
    elif avg_risk >= 60:
        return "HIGH"
    elif avg_risk >= 30:
        return "MEDIUM"
    elif avg_risk >= 10:
        return "LOW"
    else:
        return "MINIMAL"

def notify_scan_completed_with_results(scan_id: str, target: str, scan_name: str, status: str, scan_results: Dict[str, int]) -> bool:
    """Notify that a scan has completed with detailed results and risk assessment.
    
    Args:
        scan_id: Unique scan identifier
        target: Scan target
        scan_name: Human readable scan name
        status: Scan completion status
        scan_results: Dictionary of event types and their counts
        
    Returns:
        bool: True if notification was sent successfully
    """
    total_findings = sum(scan_results.values())
    risk_status = calculate_risk_status(scan_results)
    
    message = {
        'event': 'scan_completed_with_results',
        'scan_id': scan_id,
        'target': target,
        'scan_name': scan_name,
        'status': status,
        'total_findings': total_findings,
        'risk_status': risk_status,
        'results_breakdown': scan_results,
        'timestamp': time.time()
    }
    
    return _redis_pubsub.publish('scan_notifications', message)

def get_redis_instance() -> Optional[redis.Redis]:
    """Get the Redis client instance for advanced operations.
    
    Attempts to reconnect if not currently connected.
    
    Returns:
        Redis client instance or None if connection fails completely
    """
    # If not connected, try to reconnect
    if not _redis_pubsub.is_connected():
        logging.info("Redis not connected, attempting to reconnect...")
        _redis_pubsub._connect()
    
    # Return the client if connected, None if connection failed
    if _redis_pubsub.is_connected():
        return _redis_pubsub._redis_client
    else:
        logging.error("Failed to establish Redis connection")
        return None

def ensure_redis_connection() -> bool:
    """Ensure Redis connection is active, attempt reconnection if needed.
    
    Returns:
        bool: True if Redis is connected and ready
    """
    return _redis_pubsub.is_connected() or _redis_pubsub.reconnect()

def force_redis_reconnect() -> bool:
    """Force a Redis reconnection.
    
    Returns:
        bool: True if reconnection successful
    """
    return _redis_pubsub.reconnect()

def get_redis_status() -> Dict[str, Any]:
    """Get detailed Redis connection status.
    
    Returns:
        dict: Status information including connection state and server info
    """
    status = {
        'connected': False,
        'client_exists': _redis_pubsub._redis_client is not None,
        'server_info': None,
        'error': None
    }
    
    try:
        if _redis_pubsub.is_connected():
            status['connected'] = True
            if _redis_pubsub._redis_client:
                status['server_info'] = _redis_pubsub._redis_client.info('server')
        else:
            status['error'] = 'Not connected to Redis server'
    except Exception as e:
        status['error'] = str(e)
    
    return status
