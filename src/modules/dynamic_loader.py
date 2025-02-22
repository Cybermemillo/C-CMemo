"""
Módulo de carga dinámica.
Permite cargar y gestionar plugins y módulos adicionales en tiempo de ejecución.
"""

import sys
import os
import hashlib
import base64
import logging
import importlib.util
import inspect
from typing import Dict, Any, List, Callable, Optional
from dataclasses import dataclass
import json

@dataclass
class PluginInfo:
    """Información sobre un plugin cargado."""
    name: str
    version: str
    description: str
    author: str
    dependencies: List[str]
    hooks: List[str]
    module: Any
    hash: str

class DynamicLoader:
    def __init__(self):
        """Inicializa el cargador dinámico."""
        self.plugins: Dict[str, PluginInfo] = {}
        self.hooks: Dict[str, List[Callable]] = {}
        self._setup_hooks()

    def _setup_hooks(self):
        """Configura los hooks básicos del sistema."""
        self.hooks = {
            'pre_command': [],    # Antes de ejecutar un comando
            'post_command': [],   # Después de ejecutar un comando
            'on_load': [],        # Al cargar un plugin
            'on_unload': [],      # Al descargar un plugin
            'on_network': [],     # Eventos de red
            'on_file': [],        # Operaciones con archivos
            'on_process': [],     # Eventos de procesos
            'on_registry': []     # Modificaciones del registro
        }

    def load_plugin_from_memory(self, plugin_code: str, plugin_name: str) -> bool:
        """
        Carga un plugin desde código en memoria.
        
        Args:
            plugin_code: Código fuente del plugin en base64
            plugin_name: Nombre para el plugin
            
        Returns:
            bool: True si se cargó correctamente
        """
        try:
            # Decodificar código
            code = base64.b64decode(plugin_code).decode('utf-8')
            
            # Crear módulo temporal
            spec = importlib.util.spec_from_loader(plugin_name, loader=None)
            module = importlib.util.module_from_spec(spec)
            
            # Ejecutar código
            exec(code, module.__dict__)
            
            # Verificar interfaz requerida
            if not hasattr(module, 'PLUGIN_INFO'):
                raise ValueError("El plugin no proporciona información básica (PLUGIN_INFO)")
                
            # Calcular hash del código
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            
            # Registrar plugin
            info = PluginInfo(
                name=module.PLUGIN_INFO['name'],
                version=module.PLUGIN_INFO['version'],
                description=module.PLUGIN_INFO['description'],
                author=module.PLUGIN_INFO['author'],
                dependencies=module.PLUGIN_INFO.get('dependencies', []),
                hooks=module.PLUGIN_INFO.get('hooks', []),
                module=module,
                hash=code_hash
            )
            
            # Verificar dependencias
            self._check_dependencies(info.dependencies)
            
            # Registrar hooks
            self._register_hooks(info)
            
            # Almacenar plugin
            self.plugins[plugin_name] = info
            
            # Ejecutar hook de carga
            for hook in self.hooks['on_load']:
                hook(plugin_name)
                
            logging.info(f"Plugin {plugin_name} cargado correctamente")
            return True
            
        except Exception as e:
            logging.error(f"Error cargando plugin {plugin_name}: {e}")
            return False

    def unload_plugin(self, plugin_name: str) -> bool:
        """
        Descarga un plugin.
        
        Args:
            plugin_name: Nombre del plugin a descargar
            
        Returns:
            bool: True si se descargó correctamente
        """
        try:
            if plugin_name not in self.plugins:
                return False
                
            # Ejecutar hook de descarga
            for hook in self.hooks['on_unload']:
                hook(plugin_name)
                
            # Eliminar hooks del plugin
            plugin = self.plugins[plugin_name]
            for hook_name in plugin.hooks:
                if hook_name in self.hooks:
                    self.hooks[hook_name] = [h for h in self.hooks[hook_name] 
                                           if not hasattr(h, '__module__') or 
                                           h.__module__ != plugin.module.__name__]
                    
            # Eliminar referencias
            del self.plugins[plugin_name]
            del sys.modules[plugin_name]
            
            logging.info(f"Plugin {plugin_name} descargado correctamente")
            return True
            
        except Exception as e:
            logging.error(f"Error descargando plugin {plugin_name}: {e}")
            return False

    def _check_dependencies(self, dependencies: List[str]):
        """Verifica que las dependencias estén instaladas."""
        missing = []
        for dep in dependencies:
            try:
                importlib.import_module(dep)
            except ImportError:
                missing.append(dep)
        
        if missing:
            raise ImportError(f"Dependencias faltantes: {', '.join(missing)}")

    def _register_hooks(self, plugin_info: PluginInfo):
        """Registra los hooks del plugin."""
        for hook_name in plugin_info.hooks:
            if not hasattr(plugin_info.module, hook_name):
                continue
                
            if hook_name not in self.hooks:
                self.hooks[hook_name] = []
                
            hook_func = getattr(plugin_info.module, hook_name)
            self.hooks[hook_name].append(hook_func)

    def call_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """
        Ejecuta todos los hooks registrados para un evento.
        
        Args:
            hook_name: Nombre del hook a ejecutar
            *args: Argumentos posicionales
            **kwargs: Argumentos nombrados
            
        Returns:
            Lista con los resultados de cada hook
        """
        results = []
        if hook_name in self.hooks:
            for hook in self.hooks[hook_name]:
                try:
                    result = hook(*args, **kwargs)
                    results.append(result)
                except Exception as e:
                    logging.error(f"Error ejecutando hook {hook_name}: {e}")
        return results

    def get_plugin_info(self, plugin_name: str = None) -> Dict[str, Any]:
        """
        Obtiene información sobre los plugins cargados.
        
        Args:
            plugin_name: Nombre del plugin específico o None para todos
            
        Returns:
            Dict con información de los plugins
        """
        if plugin_name:
            if plugin_name not in self.plugins:
                return {}
            plugin = self.plugins[plugin_name]
            return {
                'name': plugin.name,
                'version': plugin.version,
                'description': plugin.description,
                'author': plugin.author,
                'dependencies': plugin.dependencies,
                'hooks': plugin.hooks,
                'hash': plugin.hash
            }
        
        return {
            name: {
                'name': p.name,
                'version': p.version,
                'description': p.description,
                'author': p.author,
                'dependencies': p.dependencies,
                'hooks': p.hooks,
                'hash': p.hash
            }
            for name, p in self.plugins.items()
        }

    def validate_plugin(self, plugin_code: str, expected_hash: str = None) -> bool:
        """
        Valida un plugin antes de cargarlo.
        
        Args:
            plugin_code: Código del plugin en base64
            expected_hash: Hash esperado para validación
            
        Returns:
            bool: True si el plugin es válido
        """
        try:
            # Decodificar y validar sintaxis
            code = base64.b64decode(plugin_code).decode('utf-8')
            compile(code, '<string>', 'exec')
            
            # Verificar hash si se proporciona
            if expected_hash:
                actual_hash = hashlib.sha256(code.encode()).hexdigest()
                if actual_hash != expected_hash:
                    return False
                    
            return True
        except Exception as e:
            logging.error(f"Error validando plugin: {e}")
            return False
