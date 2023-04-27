import base64
import sqlite3
import matplotlib.pyplot as plt
import io
import pandas as pd
import seaborn as sns
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
con = sqlite3.connect('database.db', check_same_thread=False)



@app.route('/')
def formulario():
    return render_template('index.html')


@app.route('/ips', methods=['POST', 'GET'])
def top_ips():
    n = int(request.form['x'])  # número de elementos a mostrar
    con = sqlite3.connect('database.db')
    df = pd.read_sql_query(f"SELECT origen, COUNT(*) as count FROM alertas GROUP BY origen ORDER BY count DESC LIMIT {n}", con)
    con.close()
    ips = df['origen'].tolist()
    counts = df['count'].tolist()

    # Crear gráfico de barras
    sns.set_style("whitegrid")

    # crear figura y ejes
    fig, ax = plt.subplots(figsize=(8, 6))

    # barras horizontales en colores alternos
    colors = ['#FF5733', '#C70039', '#900C3F', '#581845', '#FFC300']
    for i, (ip, count) in enumerate(zip(ips, counts)):
        ax.bar(i, count, color=colors[i % len(colors)], edgecolor='black', alpha=0.8)

    # ajustar posición y etiquetas en eje x
    ax.set_xticks(range(len(ips)))
    ax.set_xticklabels(ips)
    plt.xticks(rotation=15)

    # Convertir gráfico en formato base64 para mostrar en la plantilla
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    buffer = b''.join(buf)
    graph = base64.b64encode(buffer).decode('utf-8')

    return render_template('grafico.html', ips=ips, counts=counts, graph=graph, n=n)




if __name__ == '__main__':
    app.run(debug=True)
    top_ips()
    ## TODO devices
