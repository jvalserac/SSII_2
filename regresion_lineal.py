import json

from matplotlib import pyplot as plt
from sklearn import linear_model
from sklearn.metrics import accuracy_score, mean_squared_error

file = open('./data/devices_IA_clases.json')
train = json.load(file)
file = open('./data/devices_IA_predecir_v2.json')
test = json.load(file)
x_train = []
y_train = []
x_test = []
y_test = []
## Train data
for i in train:
    x_train.append([i['servicios_inseguros']])
    y_train.append(i['peligroso'])

## Testing data
for i in test:
    x_test.append([i['servicios_inseguros']])
    y_test.append(i['peligroso'])

# Linear regression
regresion = linear_model.LinearRegression()

# Training the model
regresion.fit(x_train,y_train)

prediction = regresion.predict(x_test)
print("Mean squared error: %.2f" % mean_squared_error(prediction, y_test))
plt.scatter(x_test, y_test, color="black")
plt.plot(x_test, prediction, color="blue", linewidth=3)
plt.xticks(())
plt.yticks(())
plt.show()

