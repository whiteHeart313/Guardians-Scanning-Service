#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Database monitoring utility for SpiderFoot
Monitors database changes and sends real-time notifications
"""

import time
import threading
import logging
from typing import Dict, Any, Optional, Callable
from spiderfoot import SpiderFootDb
from spiderfoot.pubsub import notify_new_finding, notify_scan_completed_with_results, calculate_risk_status


class SpiderFootDbMonitor:
    """Monitor SpiderFoot database for real-time changes."""
    
    def __init__(self, sf_config: Dict[str, Any], poll_interval: int = 2):
        """Initialize database monitor.
        
        Args:
            sf_config: SpiderFoot configuration
            poll_interval: How often to check for changes (seconds)
        """
        self.sf_config = sf_config
        self.poll_interval = poll_interval
        self.dbh = SpiderFootDb(sf_config)
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.last_event_id = {}  # Track last seen event ID per scan
        self.scan_status_cache = {}  # Cache scan statuses
        self.logger = logging.getLogger("spiderfoot.db_monitor")
        
    def start_monitoring(self, scan_id: str, target: str, scan_name: str, user_id: str = "unknown") -> None:
        """Start monitoring a specific scan.
        
        Args:
            scan_id: Scan ID to monitor
            target: Scan target
            scan_name: Human readable scan name
            user_id: User ID associated with this scan
        """
        if self.monitoring:
            self.logger.warning(f"Already monitoring scan {scan_id}")
            return
            
        self.monitoring = True
        self.last_event_id[scan_id] = 0
        self.scan_status_cache[scan_id] = {
            'target': target,
            'scan_name': scan_name,
            'user_id': user_id,
            'status': 'RUNNING',
            'event_counts': {}
        }
        
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(scan_id,),
            daemon=True
        )
        self.monitor_thread.start()
        self.logger.info(f"Started monitoring scan {scan_id}")
    
    def stop_monitoring(self) -> None:
        """Stop monitoring."""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        self.logger.info("Stopped database monitoring")
    
    def _monitor_loop(self, scan_id: str) -> None:
        """Main monitoring loop."""
        while self.monitoring:
            try:
                # Check for new events
                self._check_new_events(scan_id)
                
                # Check scan status
                self._check_scan_status(scan_id)
                
                time.sleep(self.poll_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.poll_interval)
    
    def _check_new_events(self, scan_id: str) -> None:
        """Check for new events in the database using scan summary."""
        try:
            # Get current scan results summary
            current_summary = self.dbh.scanResultSummary(scan_id, "type")
            
            if not current_summary:
                return
            
            # Get cached counts for comparison
            scan_cache = self.scan_status_cache.get(scan_id, {})
            previous_counts = scan_cache.get('event_counts', {})
            current_counts = {}
            
            # Process current summary
            for result in current_summary:
                event_type = result[0]  # Event type
                count = result[3]       # Total count (fourth column)
                current_counts[event_type] = count
                
                # Check if this is a new event type or increased count
                previous_count = previous_counts.get(event_type, 0)
                if count > previous_count:
                    # New events found for this type
                    new_count = count - previous_count
                    
                    # Send notification for important events
                    if self._is_important_event(event_type):
                        self.logger.info(f"New {event_type} events found: {new_count}")
                        # For real-time notification, we'll send one notification per new event type
                        scan_cache = self.scan_status_cache.get(scan_id, {})
                        user_id = scan_cache.get('user_id', 'unknown')
                        notify_new_finding(scan_id, event_type, f"{new_count} new findings", "database_monitor", user_id)
            
            # Update cache with current counts
            if scan_id in self.scan_status_cache:
                self.scan_status_cache[scan_id]['event_counts'] = current_counts
                
        except Exception as e:
            self.logger.error(f"Error checking new events for scan {scan_id}: {e}")
    def _check_scan_status(self, scan_id: str) -> None:
        """Check if scan status has changed."""
        try:
            scan_info = self.dbh.scanInstanceGet(scan_id)
            if not scan_info:
                return
            
            current_status = scan_info[5]  # Status is at index 5
            cached_status = self.scan_status_cache.get(scan_id, {}).get('status')
            
            if current_status != cached_status and current_status in ["FINISHED", "ERROR-FAILED", "ABORTED"]:
                # Scan completed - send final notification
                self._send_completion_notification(scan_id, current_status)
                self.monitoring = False  # Stop monitoring this scan
                
        except Exception as e:
            self.logger.error(f"Error checking scan status for {scan_id}: {e}")
    
    def _send_completion_notification(self, scan_id: str, status: str) -> None:
        """Send scan completion notification with results."""
        try:
            scan_cache = self.scan_status_cache.get(scan_id, {})
            target = scan_cache.get('target', 'Unknown')
            scan_name = scan_cache.get('scan_name', 'Unknown')
            user_id = scan_cache.get('user_id', 'unknown')
            event_counts = scan_cache.get('event_counts', {})
            
            # Send detailed completion notification
            notify_scan_completed_with_results(scan_id, target, scan_name, status, event_counts, user_id)
            
            total_findings = sum(event_counts.values())
            risk_status = calculate_risk_status(event_counts)
            
            self.logger.info(f"Scan {scan_id} completed with status {status}, "
                           f"{total_findings} findings, risk level: {risk_status}")
            
        except Exception as e:
            self.logger.error(f"Error sending completion notification: {e}")
    
    def _is_important_event(self, event_type: str) -> bool:
        """Determine if event type is important enough for real-time notification."""
        important_events = {
            'VULNERABILITY_CRITICAL',
            'VULNERABILITY_HIGH',
            'MALICIOUS_IPADDR',
            'MALICIOUS_EMAILADDR',
            'MALICIOUS_INTERNET_NAME',
            'BREACH_DATA',
            'DARKWEB_MENTION',
            'DEFACED_IPADDR',
            'DEFACED_INTERNET_NAME',
            'BLACKLISTED_IPADDR',
            'BLACKLISTED_INTERNET_NAME',
            'LEAK_SITE'
        }
        
        return event_type in important_events


# Global monitor instance
_db_monitor: Optional[SpiderFootDbMonitor] = None

def start_scan_monitoring(sf_config: Dict[str, Any], scan_id: str, target: str, scan_name: str, user_id: str = "unknown") -> None:
    """Start monitoring a scan for real-time updates.
    
    Args:
        sf_config: SpiderFoot configuration
        scan_id: Scan ID to monitor
        target: Scan target
        scan_name: Human readable scan name
        user_id: User ID associated with this scan
    """
    global _db_monitor
    
    if _db_monitor:
        _db_monitor.stop_monitoring()
    
    _db_monitor = SpiderFootDbMonitor(sf_config)
    _db_monitor.start_monitoring(scan_id, target, scan_name, user_id)

def stop_scan_monitoring() -> None:
    """Stop the current scan monitoring."""
    global _db_monitor
    
    if _db_monitor:
        _db_monitor.stop_monitoring()
        _db_monitor = None
