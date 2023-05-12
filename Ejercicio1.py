import base64
import sqlite3
import matplotlib.pyplot as plt
import io
import pandas as pd
import seaborn as sns
from flask import Flask, jsonify, render_template, request
import requests



app = Flask(__name__)
con = sqlite3.connect('database.db', check_same_thread=False)


@app.route('/')
def formulario():
    return render_template('index.html')

@app.route('/top_ips', methods=['GET'])
def top_ips():
    n = int(request.args.get('n_ips', 5))  # Top 5 ips por defecto
    con = sqlite3.connect('database.db')
    df = pd.read_sql_query(f"SELECT origen, COUNT(*) as count FROM alertas GROUP BY origen ORDER BY count DESC LIMIT {n}", con)
    con.close()
    top_ips = df.to_dict(orient='records')
    return jsonify(top_ips=top_ips)

@app.route('/top_devices', methods=['GET'])
def top_devices():
    n = int(request.args.get('n_devices', 10))  # Top 10 devices by default
    con = sqlite3.connect('database.db')
    dispositivos = pd.read_sql_query("SELECT * FROM dispositivos", con)
    analisis = pd.read_sql_query("SELECT * FROM analisis", con)
    merge = pd.merge(dispositivos, analisis, on='ip')
    vuln = analisis[['servicios_inseguros', 'vulnerabilidades_detectadas']]
    vuln['suma_vuln'] = vuln['servicios_inseguros'] + vuln['vulnerabilidades_detectadas']
    vuln_dispositivo = pd.concat([merge['ip'], vuln['suma_vuln']], axis=1)
    vuln_dispositivo_agrupado = vuln_dispositivo.groupby('ip').sum().reset_index()
    vuln_dispositivo_ordenado = vuln_dispositivo_agrupado.sort_values(by='suma_vuln', ascending=False)
    top_devices = vuln_dispositivo_ordenado.head(n)
    top_devices = top_devices[['ip', 'suma_vuln']]
    con.close()

    top_devices_list = top_devices.to_dict(orient='records')

    top_devices_dict = {'ip': top_devices['ip'].tolist(), 'suma_vuln': top_devices['suma_vuln'].tolist()}

    return jsonify(top_devices=top_devices_dict)


@app.route('/latest_cves', methods=['GET'])
def latest_cves():
    url = 'https://cve.circl.lu/api/last'
    response = requests.get(url)
    if response.status_code == 200:
        cves = response.json()[:10] # Sólo los 10 últimos
        cves_data = []
        for cve in cves:
            cve_data = {
                'id': cve['id']
            }
            cves_data.append(cve_data)
        return jsonify(cves=cves_data)
    else:
        return jsonify(error='Error al conseguir datos de https://cve.circl.lu/api/last')


if __name__ == '__main__':
    app.run(debug=True)
    top_ips()
    ## TODO devices
