import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
import logging
from settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

# Database configuration
DB_CONFIG = {
    'host': DB_HOST,
    'port': DB_PORT,
    'database': DB_NAME,
    'user': DB_USER,
    'password': DB_PASSWORD,
    'connect_timeout': 30, 
    'options': '-c statement_timeout=60000' 
}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseConnection:
    """Database connection manager"""
    
    def __init__(self, config=None):
        self.config = config or DB_CONFIG
        self._connection = None
    
    def connect(self):
        """Establish database connection"""
        try:
            self._connection = psycopg2.connect(**self.config)
            logger.info("Database connection established")
            return self._connection
        except psycopg2.Error as e:
            logger.error(f"Database connection failed: {e}")
            raise
    
    def disconnect(self):
        """Close database connection"""
        if self._connection:
            self._connection.close()
            self._connection = None
            logger.info("Database connection closed")
    
    @contextmanager
    def get_cursor(self, dict_cursor=True):
        """Context manager for database cursor"""
        if not self._connection:
            self.connect()
        
        cursor_class = RealDictCursor if dict_cursor else None
        cursor = self._connection.cursor(cursor_factory=cursor_class)
        
        try:
            yield cursor
            self._connection.commit()
        except Exception as e:
            self._connection.rollback()
            logger.exception(f"Database operation failed: {e}")
            raise
        finally:
            cursor.close()

# Global database instance
db = DatabaseConnection()

@contextmanager
def get_db_cursor(dict_cursor=True):
    """Convenience function to get database cursor"""
    with db.get_cursor(dict_cursor=dict_cursor) as cursor:
        yield cursor

def test_connection():
    """Test database connectivity"""
    try:
        with get_db_cursor() as cursor:
            cursor.execute("SELECT 1 as test")
            result = cursor.fetchone()
            logger.info(f"Database test successful: {result}")
            return True
    except Exception as e:
        logger.error(f"Database test failed: {e}")
        return False

def get_database_info():
    """Get database schema information"""
    try:
        with get_db_cursor() as cursor:
            # Get table information
            cursor.execute("""
                SELECT table_name, table_type 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
                ORDER BY table_name
            """)
            tables = cursor.fetchall()
            
            # Get view information
            cursor.execute("""
                SELECT table_name as view_name
                FROM information_schema.views 
                WHERE table_schema = 'public'
                ORDER BY table_name
            """)
            views = cursor.fetchall()
            
            return {
                'tables': tables,
                'views': views,
                'connection_info': {
                    'host': DB_CONFIG['host'],
                    'database': DB_CONFIG['database'],
                    'user': DB_CONFIG['user']
                }
            }
    except Exception as e:
        logger.error(f"Failed to get database info: {e}")
        return {'error': str(e)}
