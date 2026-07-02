# ZENIHT AI - Analizador de Red con Inteligencia Artificial

Analizador de red en tiempo real con modelo AI (Autoencoder) que detecta anomalias, identifica dispositivos y monitorea la seguridad de tu red.

## Online (funciona en celular y PC)

**https://zeniht-ai-analyzer.vercel.app**

1. Abrir la URL en tu navegador
2. Crear cuenta (usuario + password)
3. Empezar a monitorear
4. Boton "Entrenar" para activar la IA
5. Boton "Guardar en GitHub" para persistir el modelo

## Caracteristicas

- **AI en el navegador** - TensorFlow.js Autoencoder para deteccion de anomalias
- **Monitoreo en tiempo real** - Captura trafico HTTP/HTTPS del navegador
- **Identificacion de dispositivos** - Detecta tipo de dispositivo, OS, ubicacion
- **Descubrimiento de redes** - Escaneo de subredes
- **Traceroute** - Rastreo de rutas de red
- **Guardado en GitHub** - Modelo AI persistente en tu repositorio
- **Funciona en celular** - PWA instalable en Android/iOS
- **Todo en espanol** - Interfaz completamente en espanol

## Ejecutar en PC (monitoreo real de red)

```bash
# Necesita Python 3.12+ y Npcap
pip install torch numpy scikit-learn scapy joblib

# Ejecutar con monitoreo completo
python main.py --web

# Abrir http://localhost:8080
```

## Estructura

```
red iA/
├── main.py                 # Script principal Python (monitoreo real)
├── web/                    # App web (Vercel)
│   ├── index.html          # Interfaz principal
│   ├── css/style.css       # Estilos
│   ├── js/
│   │   ├── ai.js           # TensorFlow.js Autoencoder
│   │   ├── network.js      # Monitoreo de red
│   │   └── app.js          # Logica de la app
│   └── api/auth.js         # API de autenticacion
└── README.md
```

## Como funciona la IA

1. **Captura** - El navegador captura paquetes HTTP/HTTPS
2. **Features** - Extrae 16 features por paquete (tamaño, protocolo, puerto, etc.)
3. **Entrenamiento** - Autoencoder aprende el patron "normal"
4. **Deteccion** - Paquetes que no siguen el patron se marcan como anomalia
5. **Umbral** - Error de reconstruccion > umbral = anomalia

## Modelo AI

- Arquitectura: Autoencoder con batch normalization y dropout
- Features: 16 dimensiones por paquete
- Ventana: 24 paquetes consecutivos
- Entrenamiento: 30 epochs por sesion
- Umbral: Percentil 92 del error de reconstruccion

## GitHub

El modelo AI se puede guardar y cargar desde GitHub:

1. Crear un repositorio en GitHub
2. Crear un Personal Access Token
3. En la app, poner "Guardar en GitHub"
4. Ingresa tu usuario, repo y token
5. El modelo se guarda en `models/zeniht_model.json`

Para cargar desde otro dispositivo:
1. Poner "Cargar de GitHub"
2. Ingresa usuario y repo
3. El modelo se descarga y activa

## License

MIT
