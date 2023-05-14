import base64
import json
import sqlite3
from io import BytesIO

import matplotlib.pyplot as plt
from matplotlib.table import Table
import pandas as pd
from flask import Flask, jsonify, render_template, request, make_response
import requests
from sklearn import linear_model
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, mean_squared_error

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
    n = int(request.args.get('n_devices', 5))
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

@app.route('/linear_regression', methods=['GET'])
def linear_regression():
    with open('./data/devices_IA_clases.json', 'r') as file:
        train = json.load(file)

    with open('./data/devices_IA_predecir_v2.json', 'r') as file:
        predict = json.load(file)

    x_train = []
    y_train = []
    x_predict = []
    y_predict = []

    # Train data
    for i in train:
        x_train.append([i['servicios_inseguros']])
        y_train.append(i['peligroso'])

    # Testing data
    for i in predict:
        x_predict.append([i['servicios_inseguros']])
        y_predict.append(i['peligroso'])

    regresion = linear_model.LinearRegression()
    regresion.fit(x_train, y_train)
    prediction = regresion.predict(x_predict)

    mse = mean_squared_error(prediction, y_predict)
    print(f"Mean squared error: {mse:.2f}")

    x = [i[0] for i in x_predict]
    y = y_predict
    y_pred = prediction.tolist()

    data = {
        'x': x,
        'y': y,
        'y_pred': y_pred,
        'mse': mse
    }

    return jsonify(data)


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

@app.route('/download_pdf', methods=['POST'])
def download_pdf():
    top_ips_data = request.json['top_ips']
    top_ips = pd.DataFrame(top_ips_data['datasets'][0]['data'], index=top_ips_data['labels'], columns=['Top IPs'])

    top_devices_data = request.json['top_devices']
    top_devices = pd.DataFrame(top_devices_data['datasets'][0]['data'], index=top_devices_data['labels'], columns=['Top Devices'])

    cves_data = request.json['cves']
    cves = pd.DataFrame(cves_data)

    # New: Linear Regression Data
    linear_reg_data = request.json['linear_regression']
    linear_reg = pd.DataFrame(linear_reg_data, columns=['x', 'y'])

    fig, axs = plt.subplots(4, 1, figsize=(8, 16))

    # Top IPs plot
    top_ips.plot(kind='barh', ax=axs[0])
    axs[0].set_title('Top IPs')

    # Top Devices plot
    top_devices.plot(kind='barh', ax=axs[1])
    axs[1].set_title('Top Devices')

    # Linear Regression plot
    axs[2].scatter(linear_reg['x'], linear_reg['y'], color='blue')
    axs[2].plot(linear_reg['x'], linear_reg['y_pred'], color='red')
    axs[2].set_title('Linear Regression')

    # CVEs list table
    axs[3].axis('tight')
    axs[3].axis('off')
    table = Table(axs[3], bbox=[0,0,1,1])
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.add_cell(0, 0, width=1, height=0.1, text="CVEs", 
                   fill=False, loc='center', 
                   facecolor='none')
    for i, cve in enumerate(cves['id']):
        table.add_cell(i+1, 0, width=1, height=0.1, text=cve, 
                       fill=False, loc='left', 
                       facecolor='none')
    axs[3].add_table(table)
    pdf_io = BytesIO()
    fig.savefig(pdf_io, format='pdf', bbox_inches='tight')
    pdf_io.seek(0)
    
    response = make_response(pdf_io.getvalue())
    response.headers.set('Content-Type', 'application/pdf')
    response.headers.set('Content-Disposition', 'attachment', filename='report.pdf')
    
    return response


if __name__ == '__main__':
    app.run(debug=True)
