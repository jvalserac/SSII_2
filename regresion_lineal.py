import json

import pandas as pd
from sklearn import linear_model
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, mean_squared_error

file = open('./data/devices_IA_clases.json')
train = json.load(file)
file = open('./data/devices_IA_predecir_v2.json')
predict = json.load(file)
x_train = []
y_train = []
x_predict = []
y_predict = []
## Train data
for i in train:
    x_train.append([i['servicios_inseguros']])
    y_train.append(i['peligroso'])

## Testing data
for i in predict:
    x_predict.append([i['servicios_inseguros']])
    y_predict.append(i['peligroso'])

# Linear regression
regresion = linear_model.LinearRegression()

# Training the model
regresion.fit(x_train,y_train)

prediction = regresion.predict(x_predict)
print("Mean squared error: %.2f" % mean_squared_error(prediction, y_predict))
## TODO plot

