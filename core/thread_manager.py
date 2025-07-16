import threading
import logging
from typing import Dict, Optional, Callable, Any, Tuple
import time

logger = logging.getLogger(__name__)

class ThreadManager:
    def __init__(self):
        self.threads: Dict[str, threading.Thread] = {}
        self.thread_stats: Dict[str, Dict] = {}
        self._lock = threading.Lock()
    
    def start_thread(
        self,
        name: str,
        target: Callable,
        args: Tuple = (),
        kwargs: Dict = None,
        daemon: bool = True
    ) -> threading.Thread:
        
        with self._lock:
            if name in self.threads and self.threads[name].is_alive():
                logger.warning(f"Thread '{name}' is already running")
                return self.threads[name]
            
            thread = threading.Thread(
                target=self._thread_wrapper,
                name=name,
                args=(name, target, args, kwargs or {}),
                daemon=daemon
            )
            
            self.threads[name] = thread
            self.thread_stats[name] = {
                'start_time': time.time(),
                'status': 'starting',
                'errors': 0,
                'restarts': 0
            }
            
            thread.start()
            logger.info(f"Started thread '{name}'")
            
            return thread
    
    def _thread_wrapper(self, name: str, target: Callable, args: Tuple, kwargs: Dict):
        try:
            self.thread_stats[name]['status'] = 'running'
            target(*args, **kwargs)
            self.thread_stats[name]['status'] = 'completed'
            
        except Exception as e:
            logger.error(f"Thread '{name}' crashed: {e}", exc_info=True)
            self.thread_stats[name]['status'] = 'crashed'
            self.thread_stats[name]['errors'] += 1
            
            if self.thread_stats[name]['restarts'] < 3:
                logger.info(f"Attempting to restart thread '{name}'...")
                time.sleep(5)
                self.thread_stats[name]['restarts'] += 1
                self.start_thread(name, target, args, kwargs)
    
    def stop_thread(self, name: str, timeout: float = 5.0) -> bool:
        with self._lock:
            if name not in self.threads:
                logger.warning(f"Thread '{name}' not found")
                return False
            
            thread = self.threads[name]
            if not thread.is_alive():
                logger.info(f"Thread '{name}' is not running")
                return True
            
            logger.info(f"Stopping thread '{name}'...")
            self.thread_stats[name]['status'] = 'stopping'
            
            thread.join(timeout=timeout)
            
            if thread.is_alive():
                logger.warning(f"Thread '{name}' did not stop gracefully")
                return False
            
            logger.info(f"Thread '{name}' stopped")
            return True
    
    def stop_all(self, timeout: float = 5.0):
        logger.info("Stopping all threads...")
        
        threads_to_stop = list(self.threads.keys())
        for name in threads_to_stop:
            self.stop_thread(name, timeout)
    
    def get_status(self) -> Dict[str, Dict]:
        with self._lock:
            status = {}
            for name, thread in self.threads.items():
                stats = self.thread_stats.get(name, {})
                status[name] = {
                    'alive': thread.is_alive(),
                    'daemon': thread.daemon,
                    'start_time': stats.get('start_time'),
                    'status': stats.get('status', 'unknown'),
                    'errors': stats.get('errors', 0),
                    'restarts': stats.get('restarts', 0),
                    'uptime': time.time() - stats.get('start_time', time.time())
                }
            return status
    
    def restart_thread(self, name: str) -> bool:
        with self._lock:
            if name not in self.threads:
                logger.error(f"Thread '{name}' not found")
                return False
            
            logger.info(f"Restarting thread '{name}'...")
            
            original_thread = self.threads[name]
            if original_thread.is_alive():
                self.stop_thread(name)
            
            return True
    
    def monitor_threads(self):
        while True:
            try:
                with self._lock:
                    for name, thread in list(self.threads.items()):
                        if not thread.is_alive() and self.thread_stats[name]['status'] == 'running':
                            logger.warning(f"Thread '{name}' died unexpectedly")
                            self.thread_stats[name]['status'] = 'dead'
                
                time.sleep(10)
                
            except Exception as e:
                logger.error(f"Error in thread monitor: {e}")
                time.sleep(10)