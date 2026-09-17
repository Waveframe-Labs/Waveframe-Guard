"""The only additional Python import directory is immutable operator code."""
import runpy
import sys
sys.path.insert(0, '/opt/connected')
runpy.run_path('/opt/connected/cloud_server.py', run_name='__main__')
