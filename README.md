IDS: Network Anomaly Detection with Isolation Forest
Este proyecto es un Sistema de Detección de Intrusiones (IDS) híbrido desarrollado para la materia de Redes/Seguridad. El sistema captura tráfico en tiempo real mediante un sniffer en C, procesa los datos a través de un modelo de Machine Learning (Isolation Forest) en Python para detectar anomalías y visualiza los resultados en un Dashboard interactivo.

Stack:

Captura: C 

Procesamiento: Python  (Scikit-learn, Pandas, Joblib).

Comunicación: Named Pipes (FIFO) para el paso de datos entre C y Python.

Modelo: Isolation Forest (Detección de anomalías estadística/explicable).

Base de Datos: SQLite para persistencia de alertas.

Dashboard: FastAPI (Backend) + HTML/JS (Frontend).



El flujo de datos se divide en cuatro etapas críticas:

1- El sniffer en C captura paquetes y extrae características como (PPS, BPS, BPP, Flags, etc.).

2- Los datos se inyectan en un Pipe (ids_pipe) en formato CSV.

3- El motor en Python lee el pipe y aplica un escalado de datos (StandardScaler) antes de la inferencia con el modelo.

4- Al detectar una anomalía, el sistema calcula la desviación de cada característica para informar la razón técnica del baneo (ej: Flood de paquetes o Escaneo de puertos).
