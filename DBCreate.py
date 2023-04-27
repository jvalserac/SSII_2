import json
import sqlite3
import pandas as pd


con = sqlite3.connect('database.db')
cur = con.cursor()

## Creamos las tablas DISPOSITIVOS, RESPONSABLES y ANALISIS
cur.execute('''CREATE TABLE IF NOT EXISTS dispositivos (
                        id TEXT,
                        ip TEXT PRIMARY KEY,
                        localizacion TEXT,
                        responsable TEXT,
                        analisis INTEGER
)''')
cur.execute('''CREATE TABLE IF NOT EXISTS responsables (
                        nombre TEXT PRIMARY KEY,
                        telefono TEXT,
                        rol TEXT
)''')
cur.execute('''CREATE TABLE IF NOT EXISTS analisis (
                        id INTEGER,
                        ip TEXT,
                        puertos_abiertos TEXT,
                        n_puertos_abiertos INTEGER,
                        servicios INTEGER,
                        servicios_inseguros INTEGER,
                        vulnerabilidades_detectadas INTEGER
)''')

## Creamos tabla ALERTAS con el propio pandas ya que el formato de los datos permiten crearla directamente (primera fila del .csv)
alertas = pd.read_csv("./data/alerts.csv")
alertas.to_sql("alertas", con, if_exists="replace", index=False)

## Cogemos los datos de devices.json
with open("./data/devices.json", "r") as file:
    dispositivos = json.load(file)

## Insertamos los datos en las tablas (en la tabla ALERTAS ya tenemos los datos introducidos)
analisis_id = 0
for dispositivo in dispositivos:
    responsable = dispositivo['responsable']
    cur.execute("INSERT OR IGNORE INTO responsables (nombre, telefono, rol) VALUES (?, ?, ?)", (responsable['nombre'], responsable['telefono'], responsable['rol']))
    analisis = dispositivo['analisis']
    if analisis["puertos_abiertos"] == 'None':
        n_puertos_abiertos = 0
    else:
        n_puertos_abiertos = len(analisis["puertos_abiertos"])
    cur.execute("INSERT INTO analisis (id, ip, puertos_abiertos, n_puertos_abiertos, servicios, servicios_inseguros, vulnerabilidades_detectadas) VALUES (?, ?, ?, ?, ?, ?, ?)", (analisis_id, dispositivo['ip'], json.dumps(analisis['puertos_abiertos']), n_puertos_abiertos, analisis['servicios'], analisis['servicios_inseguros'], analisis['vulnerabilidades_detectadas']))
    cur.execute("INSERT INTO dispositivos (id, ip, localizacion, responsable, analisis) VALUES (?, ?, ?, ?, ?)", (dispositivo['id'], dispositivo['ip'], dispositivo['localizacion'], responsable['nombre'], analisis_id))
    analisis_id += 1

con.commit()
con.close()